import base64
import json
import os
import re
import socket
import subprocess
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse
import requests

CONFIG_PATH = "public/config.json"
TEST_URL = "https://www.gstatic.com/generate_204"
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"

def ensure_geoip_db():
    if not os.path.exists(GEOIP_DB_PATH):
        print("در حال دانلود دیتابیس GeoIP...")
        try:
            url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"
            r = requests.get(url, timeout=30)
            with open(GEOIP_DB_PATH, "wb") as f:
                f.write(r.content)
            print("دیتابیس GeoIP با موفقیت دانلود شد.")
        except Exception as e:
            print(f"خطا در دانلود GeoIP: {e}")

try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    HAS_GEOIP = False

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "profiles" in data:
                    return data
        except Exception:
            pass
    return {
        "profiles": {
            "default": {
                "brand_name": "𝔸𝕣𝕤𝕖𝕟VPℕ𓄂𓆃 ❻❽",
                "total_gb": 50,
                "expire_days": 30,
                "personal": [],
                "subs": [],
                "top_count": 50,
            }
        }
    }

def get_flag_emoji(country_code):
    if not country_code or len(country_code) != 2:
        return "🌐"
    country_code = country_code.upper()
    return chr(127397 + ord(country_code[0])) + chr(127397 + ord(country_code[1]))

def extract_host_from_node(node_link):
    try:
        if node_link.startswith("vmess://"):
            b64_data = node_link.replace("vmess://", "")
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8", errors="ignore")
            vmess_json = json.loads(decoded)
            return vmess_json.get("add", "")
        else:
            parsed = urlparse(node_link)
            return parsed.hostname or ""
    except Exception:
        return ""

def get_country_flag(node_link, reader):
    host = extract_host_from_node(node_link)
    if not host or not reader:
        return "🌐"
    try:
        ip = socket.gethostbyname(host)
        response = reader.country(ip)
        code = response.country.iso_code
        return get_flag_emoji(code)
    except Exception:
        return "🌐"

def rename_node(node_link, new_name):
    try:
        if node_link.startswith("vmess://"):
            b64_data = node_link.replace("vmess://", "")
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8", errors="ignore")
            vmess_json = json.loads(decoded)
            vmess_json["ps"] = new_name
            new_b64 = base64.b64encode(json.dumps(vmess_json, ensure_ascii=False).encode("utf-8")).decode("utf-8")
            return "vmess://" + new_b64
        elif "#" in node_link:
            base_part = node_link.split("#")[0]
            return f"{base_part}#{quote(new_name)}"
        else:
            return f"{node_link}#{quote(new_name)}"
    except Exception:
        return node_link

def decode_smart(content):
    """دکود چندلایه و رفع مشکل Padding در Base64"""
    for _ in range(3):
        content = content.strip()
        if any(p in content for p in ["vless://", "vmess://", "trojan://", "ss://"]):
            break
        try:
            missing_padding = len(content) % 4
            if missing_padding:
                content += '=' * (4 - missing_padding)
            decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
            if decoded:
                content = decoded
        except Exception:
            break
    return content

def fetch_and_decode_subs(sub_urls):
    raw_nodes = []
    pattern = re.compile(r"^(vless|vmess|trojan|ss|ssr|tuic|hysteria2)://", re.IGNORECASE)
    # تنظیم User-Agent نرم‌افزارهای V2ray برای جلوگیری از مسدودسازی توسط پنل‌ها
    headers = {
        "User-Agent": "v2rayNG/1.8.5 (Linux; Android 12)"
    }

    seen_nodes = set()

    for url in sub_urls:
        url = url.strip()
        if not url:
            continue
        try:
            r = requests.get(url, headers=headers, timeout=15)
            content = r.text.strip()
            content = decode_smart(content)

            for line in content.splitlines():
                line = line.strip()
                if pattern.match(line):
                    if line not in seen_nodes:
                        seen_nodes.add(line)
                        raw_nodes.append(line)
        except Exception as e:
            print(f"خطا در دریافت ساب {url}: {e}")

    return raw_nodes

def convert_node(node_link, target_format):
    try:
        cmd = [
            "./subconverter/subconverter",
            "-g",
            "--generate-mode", "single",
            "--url", node_link,
            "--target", target_format
        ]
        res = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=8)
        return res.decode("utf-8")
    except Exception:
        return None

def create_info_node(total_gb, expire_days):
    info_title = f"📊 Traffic: {total_gb} GB | ⏳ Remaining: {expire_days} Days"
    return f"vless://00000000-0000-0000-0000-000000000000@127.0.0.1:8080?type=tcp#{quote(info_title)}"

def generate_outputs(profile_name, final_nodes, total_gb, expire_days):
    os.makedirs("public", exist_ok=True)
    suffix = "" if profile_name == "default" else f"_{profile_name}"

    info_node = create_info_node(total_gb, expire_days)
    all_nodes_with_info = [info_node] + final_nodes

    # خروجی V2Ray Base64
    b64_out = base64.b64encode("\n".join(all_nodes_with_info).encode("utf-8")).decode("utf-8")
    with open(f"public/sub{suffix}.txt", "w", encoding="utf-8") as f:
        f.write(b64_out)

    joined_nodes = "|".join(final_nodes)

    # خروجی Clash
    clash_yaml = convert_node(joined_nodes, "clash")
    if clash_yaml:
        with open(f"public/clash{suffix}.yaml", "w", encoding="utf-8") as f:
            f.write(clash_yaml)

    # خروجی Sing-box
    singbox_json = convert_node(joined_nodes, "singbox")
    if singbox_json:
        with open(f"public/singbox{suffix}.json", "w", encoding="utf-8") as f:
            f.write(singbox_json)

def cleanup_removed_profiles(active_profiles):
    os.makedirs("public", exist_ok=True)
    for fname in os.listdir("public"):
        if fname.startswith("sub_") or fname.startswith("clash_") or fname.startswith("singbox_"):
            prof = fname.split("_", 1)[1].replace(".txt", "").replace(".yaml", "").replace(".json", "")
            if prof not in active_profiles:
                try:
                    os.remove(os.path.join("public", fname))
                except Exception:
                    pass

def main():
    ensure_geoip_db()
    
    reader = None
    if HAS_GEOIP and os.path.exists(GEOIP_DB_PATH):
        try:
            reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception:
            pass

    config = load_config()
    profiles = config.get("profiles", {})

    cleanup_removed_profiles(profiles.keys())
    print(f"شروع فرایند برای {len(profiles)} پروفایل...")

    for prof_name, prof_data in profiles.items():
        print(f"\n--- در حال پردازش پروفایل: {prof_name} ---")
        personal_nodes = prof_data.get("personal", [])
        sub_urls = prof_data.get("subs", [])
        top_count = prof_data.get("top_count", 50)
        brand_name = prof_data.get("brand_name", "𝔸𝕣𝕤𝕖𝕟VPℕ𓄂𓆃 ❻❽")
        total_gb = prof_data.get("total_gb", 50)
        expire_days = prof_data.get("expire_days", 30)

        dynamic_nodes = fetch_and_decode_subs(sub_urls)
        print(f"تعداد {len(dynamic_nodes)} سرور از لینک‌های ساب دریافت شد.")

        # انتخاب حداکثر تعداد کانفیگ‌های درخواستی
        selected_dynamic = dynamic_nodes[:top_count]

        renamed_dynamic = []
        for idx, node in enumerate(selected_dynamic, start=1):
            flag = get_country_flag(node, reader)
            custom_title = f"{flag} {brand_name} - {idx:02d}"
            renamed_dynamic.append(rename_node(node, custom_title))

        final_nodes = personal_nodes + renamed_dynamic
        generate_outputs(prof_name, final_nodes, total_gb, expire_days)

    if reader:
        reader.close()

    print("\nعملیات ساخت کلیه پروفایل‌ها با موفقیت تمام شد.")

if __name__ == "__main__":
    main()

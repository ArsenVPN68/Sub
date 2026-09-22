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
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
TEST_URL = "https://www.gstatic.com/generate_204"

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

def extract_host_and_port(node_link):
    try:
        if node_link.startswith("vmess://"):
            b64_data = node_link.replace("vmess://", "")
            b64_data += "=" * (-len(b64_data) % 4)
            decoded = base64.b64decode(b64_data).decode("utf-8", errors="ignore")
            vmess_json = json.loads(decoded)
            return vmess_json.get("add", ""), int(vmess_json.get("port", 443))
        else:
            parsed = urlparse(node_link)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme in ["vless", "trojan", "https"] else 80)
            return host, int(port)
    except Exception:
        return "", 0

def get_country_flag(node_link, reader):
    host, _ = extract_host_and_port(node_link)
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
    headers = {"User-Agent": "v2rayNG/1.8.5 (Linux; Android 12)"}
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

def test_real_ping(node_info):
    """تست واقعی رد شدن دیتا و داشتن اینترنت سالم (Real Ping Test)"""
    index, node_link = node_info
    port = 12000 + (index % 500)

    # تبدیل کانفیگ به ساختار قابل اجرای Xray
    json_str = convert_node(node_link, "v2ray")
    if not json_str:
        return node_link, False, 9999

    try:
        outbound_config = json.loads(json_str)
    except Exception:
        return node_link, False, 9999

    config_filename = f"temp_xray_{port}.json"
    full_config = {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [outbound_config]
    }

    with open(config_filename, "w", encoding="utf-8") as f:
        json.dump(full_config, f)

    # اجرای هسته Xray برای تست واقعی
    proc = subprocess.Popen(
        ["./xray", "run", "-c", config_filename],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.2)

    proxies = {
        "http": f"socks5h://127.0.0.1:{port}",
        "https": f"socks5h://127.0.0.1:{port}"
    }

    is_alive = False
    ping_time = 9999

    try:
        t0 = time.time()
        # تست با سرور گوگلی ۲۰۴ که در صورت عبور موفق دیتای اینترنت کد ۲۰۴ یا ۲۰۰ می‌دهد
        res = requests.get(TEST_URL, proxies=proxies, timeout=3.5)
        if res.status_code in [200, 204]:
            is_alive = True
            ping_time = (time.time() - t0) * 1000
    except Exception:
        pass
    finally:
        proc.terminate()
        proc.wait()
        if os.path.exists(config_filename):
            os.remove(config_filename)

    return node_link, is_alive, ping_time

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

    b64_out = base64.b64encode("\n".join(all_nodes_with_info).encode("utf-8")).decode("utf-8")
    with open(f"public/sub{suffix}.txt", "w", encoding="utf-8") as f:
        f.write(b64_out)

    joined_nodes = "|".join(final_nodes)

    clash_yaml = convert_node(joined_nodes, "clash")
    if clash_yaml:
        with open(f"public/clash{suffix}.yaml", "w", encoding="utf-8") as f:
            f.write(clash_yaml)

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
        print(f"تعداد {len(dynamic_nodes)} سرور اولیه دریافت شد. در حال انجام تست سلامت واقعی (Real Ping)...")

        alive_nodes = []
        if dynamic_nodes:
            indexed_nodes = list(enumerate(dynamic_nodes))
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(test_real_ping, item) for item in indexed_nodes]
                for future in as_completed(futures):
                    node, is_alive, ping = future.result()
                    if is_alive:
                        alive_nodes.append((node, ping))

            alive_nodes.sort(key=lambda x: x[1])
            selected_dynamic = [x[0] for x in alive_nodes[:top_count]]
            print(f"تعداد {len(selected_dynamic)} سرور با اینترنت واقعی و سالم انتخاب شد.")
        else:
            selected_dynamic = []

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

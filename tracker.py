import os
import sys
import socket
import time
import requests
from tabulate import tabulate
from urllib.parse import urlparse

def install_missing_modules():
    required_modules = ["requests", "tabulate"]
    missing_modules = []
    for module in required_modules:
        try:
            __import__(module)
        except ModuleNotFoundError:
            missing_modules.append(module)
    if missing_modules:
        print("\n📦 Modules not installed:", ", ".join(missing_modules))
        print("1. Run: pip install", " ".join(missing_modules))
        if input("\n🛠️  Install automatically? (y/n): ").lower() == 'y':
            os.system(f"{sys.executable} -m pip install {' '.join(missing_modules)}")
            print("\n✅ Modules installed successfully. Please restart the script.")
            sys.exit()
        else:
            print("\n❌ Required modules not installed. Exiting...")
            sys.exit()

install_missing_modules()

def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("""
    \033[1;35m
    ██╗██████╗      ████████╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗ 
    ██║██╔══██╗     ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗
    ██║██████╔╝█████╗  ██║   ██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝
    ██║██╔═══╝ ╚════╝  ██║   ██╔══██╗██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗
    ██║██║             ██║   ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║
    ╚═╝╚═╝             ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

    \033[0m
    \033[1;36mVersion 1.3 | Terminal Edition | Enhanced Tracking\033[0m
    """)

def print_status(message, success=True):
    color = "\033[1;32m" if success else "\033[1;31m"
    print(f"{color}↳ {message}\033[0m")

def check_internet():
    try:
        requests.get("https://www.google.com", timeout=5)
        return True
    except:
        print_status("❌ No internet connection", False)
        return False

def resolve_target(target):
    try:
        parsed = urlparse(target)
        if parsed.scheme:
            target = parsed.netloc or parsed.path
        target = target.strip().split('/')[0]
        ip = socket.gethostbyname(target)
        if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("192.168.") or ip.startswith("10."):
            print_status(f"⚠️ Warning: Resolved to local/private IP: {ip}", False)
        else:
            print_status(f"🔁 Resolved {target} → {ip}")
        return ip
    except Exception as e:
        print_status(f"❌ Failed to resolve: {target}", False)
        return None

def get_ip_info(ip):
    services = [
        "https://ipinfo.io/{}/json",
        "https://ipapi.co/{}/json/",
        "http://ip-api.com/json/{}"
    ]
    for service in services:
        try:
            url = service.format(ip)
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if 'ip' not in data or ip == data.get("ip", ip):
                    return data
        except:
            continue
    return None

def display_info(target_input):
    ip = resolve_target(target_input)
    if not ip:
        return
    print_status("🌐 Fetching information...")
    info = get_ip_info(ip)
    if not info:
        print_status("❌ Failed to retrieve data from all services", False)
        return
    service = "ipinfo.io" if "ipinfo.io" in info.get("readme", "") else "ipapi.co" if "ipapi.co" in info.get("license", "") else "ip-api.com"
    coords = info.get("loc", "")
    if coords:
        try:
            lat, lon = map(float, coords.split(","))
            if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                coords = "Invalid coordinates"
        except:
            coords = "Invalid format"
    data = [
        ["Target", f"\033[1m{target_input}\033[0m"],
        ["Resolved IP", f"\033[1;34m{info.get('ip', 'N/A')}\033[0m"],
        ["Service", service],
        ["", ""],
        ["Country", f"{info.get('country', 'N/A')} ({info.get('country_name', '')})"],
        ["Region", info.get('region', info.get('region_name', 'N/A'))],
        ["City", info.get('city', 'N/A')],
        ["Postal Code", info.get('postal', info.get('zip', 'N/A'))],
        ["Coordinates", coords],
        ["Timezone", info.get('timezone', 'N/A')],
        ["", ""],
        ["Organization", info.get('org', info.get('asn', 'N/A'))],
        ["ISP", info.get('isp', info.get('org', 'N/A'))],
    ]
    print("\n\033[1;36m📊 TARGET INFORMATION\033[0m")
    print(tabulate(data, tablefmt="fancy_grid", colalign=("right", "left")))
    filename = f"ipinfo_{ip}.txt"
    try:
        with open(filename, "w") as f:
            for item in data:
                if item[0]:
                    f.write(f"{item[0]}: {item[1].replace('\033[0m','').replace('\033[1m','').replace('\033[1;34m','')}\n")
        print_status(f"💾 Results saved to {filename}")
    except Exception as e:
        print_status(f"❌ Failed to save file: {str(e)}", False)

def get_own_ip():
    services = [
        "https://api.ipify.org",
        "https://ident.me",
        "https://checkip.amazonaws.com"
    ]
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                ip = response.text.strip()
                if ip.count('.') == 3 and all(0 <= int(part) < 256 for part in ip.split('.')):
                    return ip
        except:
            continue
    print_status("❌ Failed to detect public IP", False)
    return ""

def menu():
    print_banner()
    while True:
        print("\n\033[1;35mMAIN MENU\033[0m")
        print("\033[1m1. 🔍 Track IP/Domain\033[0m")
        print("\033[1m2. 🌐 Detect My IP & Track\033[0m")
        print("\033[1m3. 🛠️  Install Modules\033[0m")
        print("\033[1m0. 🚪 Exit\033[0m")
        choice = input("\n\033[1;36m⌨  Select option: \033[0m")
        if choice == "1":
            target = input("\n\033[1;33m🌎 Enter IP or Domain: \033[0m").strip()
            if target:
                display_info(target)
            else:
                print_status("❌ Please enter a valid target", False)
        elif choice == "2":
            if not check_internet():
                continue
            print_status("🔍 Detecting your public IP...")
            ip = get_own_ip()
            if ip:
                print_status(f"🌐 Your Public IP: \033[1;34m{ip}\033[0m")
                display_info(ip)
        elif choice == "3":
            print_status("🛠️  Installing required modules...")
            os.system(f"{sys.executable} -m pip install --upgrade requests tabulate")
            print_status("✅ Modules installed/updated. Please restart the script.")
        elif choice == "0":
            print("\n\033[1;35m👋 Exiting... Thank you for using IP-Tracker!\033[0m\n")
            break
        else:
            print_status("❌ Invalid selection", False)
        input("\n\033[1;33mPress Enter to continue...\033[0m")
        print_banner()

if __name__ == "__main__":
    try:
        menu()
    except KeyboardInterrupt:
        print("\n\n\033[1;31m⚠️  Operation cancelled by user. Exiting...\033[0m")
        sys.exit()


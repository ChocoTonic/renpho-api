#!/usr/bin/env python3
"""
Renpho Scale Data Puller
========================
Pulls body composition measurements from Renpho's encrypted API
at cloud.renpho.com.

Based on reverse-engineering from:
https://github.com/forkerer/RenphoGarminSync-CLI

USAGE:
------
  1. pip install requests pycryptodome python-dotenv
  2. Create a .env file:
       RENPHO_EMAIL=your@email.com
       RENPHO_PASSWORD=your_plain_text_password
  3. python renpho_pull.py
"""

import os
import sys
import json
import base64
import datetime
import time
import requests
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RENPHO_EMAIL = os.getenv("RENPHO_EMAIL", "")
RENPHO_PASSWORD = os.getenv("RENPHO_PASSWORD", "")
DEBUG = os.getenv("RENPHO_DEBUG", "").lower() in ("1", "true", "yes")

# From RenphoGarminSync-CLI config.json
API_BASE_URL = "https://cloud.renpho.com"
ENCRYPTION_KEY = "ed*wijdi$h6fe3ew"  # 16-byte AES-128 key
APP_VERSION = "6.6.0"
PLATFORM = "android"

OUTPUT_DIR = Path("renpho_data")

# Endpoints (from RenphoApiEndpoints.cs)
ENDPOINTS = {
    "login": "renpho-aggregation/user/login",
    "token_time": "RenphoHealth/app/sync/getTokenTime",
    "device_info": "renpho-aggregation/device/count",
    "family": "RenphoHealth/centerUser/queryFamilyMemberList",
    "measurements": "RenphoHealth/scale/queryAllMeasureDataList",
}

# Body weight scale device types
BODY_WEIGHT_SCALES = [
    "01",
    "02",
    "03",
    "04",
    "05",
    "06",
    "07",
    "08",
    "09",
    "0A",
    "0B",
    "0C",
    "0D",
    "0E",
    "0F",
    "10",
    "11",
    "12",
    "13",
    "14",
]


# ---------------------------------------------------------------------------
# AES-128-ECB Encryption (matches C# AesUtility)
# ---------------------------------------------------------------------------
def aes_encrypt(plaintext: str, key: str) -> str:
    """Encrypt string with AES-128-ECB + PKCS7 padding, return base64."""
    cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
    padded = pad(plaintext.encode("utf-8"), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode("utf-8")


def aes_decrypt(encrypted_b64: str, key: str) -> str:
    """Decrypt base64 AES-128-ECB + PKCS7 string."""
    cipher = AES.new(key.encode("utf-8"), AES.MODE_ECB)
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted.decode("utf-8")


def encrypt_request(obj) -> dict:
    """Encrypt a request payload into {"encryptData": "..."} format."""
    serialized = json.dumps(obj, separators=(",", ":"))
    return {"encryptData": aes_encrypt(serialized, ENCRYPTION_KEY)}


def encrypt_empty_object() -> dict:
    """Encrypt empty JSON object {} — for endpoints like QueryMembers."""
    return encrypt_request({})


def encrypt_empty_bytes() -> dict:
    """Encrypt empty byte array — for endpoints like GetDeviceInfo."""
    cipher = AES.new(ENCRYPTION_KEY.encode("utf-8"), AES.MODE_ECB)
    padded = pad(b"", AES.block_size)
    encrypted = cipher.encrypt(padded)
    return {"encryptData": base64.b64encode(encrypted).decode("utf-8")}


def decrypt_response(encrypted_data: str):
    """Decrypt the 'data' field from an API response."""
    decrypted = aes_decrypt(encrypted_data, ENCRYPTION_KEY)
    return json.loads(decrypted)


def check_response(result: dict, context: str = "API call") -> bool:
    """Check if API response indicates success."""
    code = result.get("code")
    msg = result.get("msg", "")
    if msg.lower() == "success" or code in (
        0,
        "0",
        101,
        "101",
        200,
        "200",
        20000,
        "20000",
    ):
        return True
    print(f"⚠️  {context} failed: code={code}, msg={msg}")
    return False


# ---------------------------------------------------------------------------
# Renpho API Client
# ---------------------------------------------------------------------------
class RenphoClient:
    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self.token = None
        self.user_id = None
        self.user_info = None
        self.session = requests.Session()

    def _post(self, endpoint: str, body: dict, auth: bool = True) -> dict:
        """Make an encrypted POST request."""
        url = f"{API_BASE_URL}/{endpoint}"
        headers = {}
        if auth and self.token:
            headers["token"] = self.token
            headers["userId"] = str(self.user_id)
            headers["appVersion"] = APP_VERSION
            headers["platform"] = PLATFORM

        if DEBUG:
            print(f"   POST {url}")
            if auth and self.token:
                print(f"   Headers: token={self.token[:20]}..., userId={self.user_id}")

        resp = self.session.post(url, json=body, headers=headers)

        if DEBUG:
            print(f"   Status: {resp.status_code}")
            print(f"   Response: {resp.text[:300]}")

        resp.raise_for_status()
        return resp.json()

    def login(self) -> dict:
        """Authenticate and get session token."""
        login_payload = {
            "questionnaire": {},
            "login": {
                "password": self.password,
                "areaCode": "US",
                "appRevision": APP_VERSION,
                "cellphoneType": "PythonScript",
                "systemType": "11",
                "email": self.email,
                "platform": PLATFORM,
            },
            "bindingList": {
                "deviceTypes": BODY_WEIGHT_SCALES,
            },
        }

        print(f"🔐 Logging in as {self.email}...")
        encrypted_body = encrypt_request(login_payload)
        result = self._post(ENDPOINTS["login"], encrypted_body, auth=False)

        if not check_response(result, "Login"):
            sys.exit(1)

        user_data = decrypt_response(result["data"])

        if DEBUG:
            print(f"   Decrypted login: {json.dumps(user_data, indent=2)[:500]}")

        login_info = user_data.get("login", {})
        self.token = login_info.get("token")
        self.user_id = login_info.get("id")
        self.user_info = login_info

        if not self.token:
            print("❌ No token in login response")
            sys.exit(1)

        print(f"✅ Logged in! User ID: {self.user_id}")
        return user_data

    def get_device_info(self) -> dict:
        """
        Get device info including scale table names and record counts.
        Uses GetEmpty(key, false) = encrypted empty bytes.
        """
        print("📱 Getting device info...")
        # C# uses GetEmpty(key, false) = encrypted empty bytes
        # Try empty bytes first, fall back to empty JSON object
        for attempt, body_fn in enumerate([encrypt_empty_bytes, encrypt_empty_object]):
            encrypted_body = body_fn()
            try:
                result = self._post(ENDPOINTS["device_info"], encrypted_body)
                break
            except requests.exceptions.HTTPError as e:
                if attempt == 0:
                    if DEBUG:
                        print(
                            f"   Attempt 1 failed ({e}), retrying with empty object..."
                        )
                    continue
                raise

        if not check_response(result, "GetDeviceInfo"):
            return {}

        data = decrypt_response(result["data"])

        if DEBUG:
            print(f"   Device info: {json.dumps(data, indent=2)[:500]}")

        return data

    def get_measurements(self, table_name: str, user_id, total_count: int) -> list:
        """
        Query all measurement data with pagination.

        Args:
            table_name: From device info (dynamic table name)
            user_id: The user ID to query for
            total_count: Total records available (from device info)
        """
        PAGE_SIZE = 50
        all_measurements = []
        page = 1

        print(
            f"📏 Fetching measurements (table: {table_name}, total: {total_count})..."
        )

        while len(all_measurements) < total_count:
            request_data = {
                "pageNum": page,
                "pageSize": PAGE_SIZE,
                "userIds": [str(user_id)],
                "tableName": table_name,
            }

            if DEBUG:
                print(f"   Page {page} (got {len(all_measurements)} so far)...")

            encrypted_body = encrypt_request(request_data)
            result = self._post(ENDPOINTS["measurements"], encrypted_body)

            if not check_response(result, f"Measurements page {page}"):
                break

            if not result.get("data"):
                break

            page_data = decrypt_response(result["data"])

            if DEBUG:
                if isinstance(page_data, list):
                    print(f"   Got {len(page_data)} records")
                else:
                    print(f"   Response type: {type(page_data)}")

            # Handle response format
            if isinstance(page_data, list):
                records = page_data
            elif isinstance(page_data, dict):
                records = None
                for key in ["list", "data", "records", "measurements"]:
                    if key in page_data and isinstance(page_data[key], list):
                        records = page_data[key]
                        break
                if records is None:
                    if "weight" in page_data:
                        records = [page_data]
                    else:
                        print(f"   ⚠️  Unexpected format: {list(page_data.keys())}")
                        break
            else:
                break

            if not records:
                break

            all_measurements.extend(records)
            page += 1

        return all_measurements


# ---------------------------------------------------------------------------
# Display and Export
# ---------------------------------------------------------------------------
DISPLAY_METRICS = [
    ("weight", "Weight", "kg"),
    ("bmi", "BMI", ""),
    ("bodyfat", "Body Fat", "%"),
    ("water", "Body Water", "%"),
    ("muscle", "Muscle Mass", "%"),
    ("bone", "Bone Mass", "%"),
    ("bmr", "BMR", "kcal/day"),
    ("visfat", "Visceral Fat", "level"),
    ("subfat", "Subcutaneous Fat", "%"),
    ("protein", "Protein", "%"),
    ("bodyage", "Body Age", "years"),
    ("sinew", "Lean Body Mass", "kg"),
    ("fatFreeWeight", "Fat Free Weight", "kg"),
    ("heartRate", "Heart Rate", "bpm"),
    ("cardiacIndex", "Cardiac Index", ""),
    ("bodyShape", "Body Shape", ""),
]


def format_timestamp(ts) -> str:
    if ts is None:
        return "unknown"
    ts = int(ts)
    if ts > 1e12:
        ts = ts // 1000
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def print_measurement(m: dict, index: int = 0):
    ts = m.get("timeStamp") or m.get("time_stamp")
    local = m.get("localCreatedAt", "")
    print(f"\n{'='*55}")
    print(f"  Measurement #{index + 1}  —  {format_timestamp(ts)}")
    if local:
        print(f"  Local time: {local}")
    scale = m.get("scaleName", "")
    if scale:
        print(f"  Scale: {scale}")
    print(f"{'='*55}")

    for key, label, unit in DISPLAY_METRICS:
        value = m.get(key)
        if value is not None and value != 0 and value != 0.0:
            unit_str = f" {unit}" if unit else ""
            print(f"  {label:<22} {value}{unit_str}")


def save_json(data, filename: str):
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / filename
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"💾 Saved to {filepath}")


def save_csv(measurements: list, filename: str = "measurements.csv"):
    if not measurements:
        return
    OUTPUT_DIR.mkdir(exist_ok=True)
    filepath = OUTPUT_DIR / filename

    priority = [
        "timeStamp",
        "localCreatedAt",
        "weight",
        "bmi",
        "bodyfat",
        "water",
        "muscle",
        "bone",
        "bmr",
        "visfat",
        "subfat",
        "protein",
        "bodyage",
        "sinew",
        "fatFreeWeight",
        "heartRate",
        "cardiacIndex",
        "bodyShape",
        "scaleName",
        "height",
        "gender",
    ]

    all_keys = set()
    for m in measurements:
        all_keys.update(m.keys())

    sorted_keys = [k for k in priority if k in all_keys]
    sorted_keys += sorted(k for k in all_keys if k not in sorted_keys)

    with open(filepath, "w") as f:
        f.write(",".join(sorted_keys) + "\n")
        for m in measurements:
            row = []
            for k in sorted_keys:
                val = m.get(k, "")
                val_str = str(val).replace(",", ";") if val is not None else ""
                row.append(val_str)
            f.write(",".join(row) + "\n")

    print(f"📊 Saved CSV to {filepath}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    if not RENPHO_EMAIL or not RENPHO_PASSWORD:
        print("❌ Missing credentials!")
        print()
        print("Create a .env file with:")
        print("  RENPHO_EMAIL=your@email.com")
        print("  RENPHO_PASSWORD=your_plain_text_password")
        print("  RENPHO_DEBUG=1  # optional")
        sys.exit(1)

    client = RenphoClient(RENPHO_EMAIL, RENPHO_PASSWORD)
    client.login()

    # Step 2: Get device info to find table name and record count
    device_info = client.get_device_info()

    if not device_info:
        print("❌ Could not get device info")
        sys.exit(1)

    save_json(device_info, "device_info.json")

    scales = device_info.get("scale", [])
    if not scales:
        print("❌ No scales found in device info")
        print(f"   Device info keys: {list(device_info.keys())}")
        sys.exit(1)

    print(f"\n⚖️  Found {len(scales)} scale table(s):")
    for i, scale in enumerate(scales):
        table = scale.get("tableName", "unknown")
        count = scale.get("count", 0)
        uids = scale.get("userIds", [])
        print(f"   [{i}] table={table}, records={count}, users={uids}")

    # Step 3: Query measurements from each scale table
    all_measurements = []
    for scale in scales:
        table_name = scale.get("tableName")
        count = scale.get("count", 0)
        user_ids = scale.get("userIds", [])

        if not table_name or count == 0:
            continue

        uid = client.user_id
        if user_ids and uid not in user_ids:
            uid = user_ids[0]

        measurements = client.get_measurements(table_name, uid, count)
        all_measurements.extend(measurements)

    if not all_measurements:
        print("\n😕 No measurements found.")
        print("   Try setting RENPHO_DEBUG=1 to see API responses.")
        return

    # Sort by timestamp (newest first)
    all_measurements.sort(
        key=lambda m: m.get("timeStamp", 0) or 0,
        reverse=True,
    )

    print(f"\n📋 Total: {len(all_measurements)} measurement(s)")

    for i, m in enumerate(all_measurements[:5]):
        print_measurement(m, i)

    if len(all_measurements) > 5:
        print(f"\n   ... and {len(all_measurements) - 5} more")

    save_json(all_measurements, "measurements.json")
    save_csv(all_measurements)

    if client.user_info:
        save_json(client.user_info, "user_profile.json")

    print(f"\n✅ Done! Data saved to '{OUTPUT_DIR}/' folder.")


if __name__ == "__main__":
    main()

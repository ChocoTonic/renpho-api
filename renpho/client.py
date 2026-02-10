"""Renpho API client for fetching scale measurements."""

import json
import sys

import requests

from .constants import (
    API_BASE_URL,
    APP_VERSION,
    BODY_WEIGHT_SCALES,
    ENDPOINTS,
    PLATFORM,
    SUCCESS_CODES,
)
from .crypto import (
    decrypt_response,
    encrypt_empty_bytes,
    encrypt_empty_object,
    encrypt_request,
)


class RenphoAPIError(Exception):
    """Raised when the Renpho API returns an error response."""

    def __init__(self, context: str, code, msg: str):
        self.context = context
        self.code = code
        self.msg = msg
        super().__init__(f"{context} failed: code={code}, msg={msg}")


def _check_response(result: dict, context: str = "API call") -> None:
    """Raise :class:`RenphoAPIError` if the response indicates failure."""
    code = result.get("code")
    msg = result.get("msg", "")
    if msg.lower() == "success" or code in SUCCESS_CODES:
        return
    raise RenphoAPIError(context, code, msg)


class RenphoClient:
    """Client for the Renpho cloud API.

    Example::

        client = RenphoClient("user@example.com", "password")
        client.login()
        measurements = client.get_all_measurements()
        for m in measurements:
            print(m["weight"], m.get("bodyfat"))
    """

    def __init__(self, email: str, password: str, *, debug: bool = False):
        self.email = email
        self.password = password
        self.debug = debug
        self.token: str | None = None
        self.user_id: int | str | None = None
        self.user_info: dict | None = None
        self._session = requests.Session()

    # ----- internal helpers -----

    def _post(self, endpoint: str, body: dict, *, auth: bool = True) -> dict:
        """Make an encrypted POST request to the Renpho API."""
        url = f"{API_BASE_URL}/{endpoint}"
        headers: dict[str, str] = {}
        if auth and self.token:
            headers["token"] = self.token
            headers["userId"] = str(self.user_id)
            headers["appVersion"] = APP_VERSION
            headers["platform"] = PLATFORM

        if self.debug:
            print(f"  POST {url}")
            if auth and self.token:
                print(f"  Headers: token={self.token[:20]}..., userId={self.user_id}")

        resp = self._session.post(url, json=body, headers=headers)

        if self.debug:
            print(f"  Status: {resp.status_code}")
            print(f"  Response: {resp.text[:300]}")

        resp.raise_for_status()
        return resp.json()

    # ----- public API -----

    def login(self) -> dict:
        """Authenticate and store the session token.

        Returns the full decrypted login response (includes user profile).

        Raises:
            RenphoAPIError: If the API rejects the credentials.
            requests.HTTPError: On transport-level failures.
        """
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

        encrypted_body = encrypt_request(login_payload)
        result = self._post(ENDPOINTS["login"], encrypted_body, auth=False)
        _check_response(result, "Login")

        user_data = decrypt_response(result["data"])

        if self.debug:
            print(f"  Decrypted login: {json.dumps(user_data, indent=2)[:500]}")

        login_info = user_data.get("login", {})
        self.token = login_info.get("token")
        self.user_id = login_info.get("id")
        self.user_info = login_info

        if not self.token:
            raise RenphoAPIError("Login", None, "No token in login response")

        return user_data

    def get_device_info(self) -> dict:
        """Get device info including scale table names and record counts.

        Returns:
            Decrypted device info dict (contains ``scale`` list among others).

        Raises:
            RenphoAPIError: On API-level failure.
        """
        for attempt, body_fn in enumerate([encrypt_empty_bytes, encrypt_empty_object]):
            encrypted_body = body_fn()
            try:
                result = self._post(ENDPOINTS["device_info"], encrypted_body)
                break
            except requests.exceptions.HTTPError as e:
                if attempt == 0:
                    if self.debug:
                        print(f"  Attempt 1 failed ({e}), retrying with empty object...")
                    continue
                raise

        _check_response(result, "GetDeviceInfo")
        data = decrypt_response(result["data"])

        if self.debug:
            print(f"  Device info: {json.dumps(data, indent=2)[:500]}")

        return data

    def get_measurements(
        self, table_name: str, user_id, total_count: int, *, page_size: int = 50
    ) -> list[dict]:
        """Fetch measurements from a specific scale table with pagination.

        Args:
            table_name: Dynamic table name from :meth:`get_device_info`.
            user_id: The user ID to query for.
            total_count: Total records available (from device info).
            page_size: Records per page (default 50).

        Returns:
            List of measurement dicts.
        """
        all_measurements: list[dict] = []
        page = 1

        while len(all_measurements) < total_count:
            request_data = {
                "pageNum": page,
                "pageSize": page_size,
                "userIds": [str(user_id)],
                "tableName": table_name,
            }

            if self.debug:
                print(f"  Page {page} (got {len(all_measurements)} so far)...")

            encrypted_body = encrypt_request(request_data)
            result = self._post(ENDPOINTS["measurements"], encrypted_body)
            _check_response(result, f"Measurements page {page}")

            if not result.get("data"):
                break

            page_data = decrypt_response(result["data"])

            if self.debug:
                if isinstance(page_data, list):
                    print(f"  Got {len(page_data)} records")
                else:
                    print(f"  Response type: {type(page_data)}")

            records = self._extract_records(page_data)
            if records is None:
                break

            all_measurements.extend(records)
            page += 1

        return all_measurements

    def get_all_measurements(self) -> list[dict]:
        """High-level helper: fetch device info then pull all measurements.

        Calls :meth:`login` first if no token is set.

        Returns:
            List of measurement dicts sorted by timestamp (newest first).
        """
        if not self.token:
            self.login()

        device_info = self.get_device_info()
        scales = device_info.get("scale", [])

        all_measurements: list[dict] = []
        for scale in scales:
            table_name = scale.get("tableName")
            count = scale.get("count", 0)
            user_ids = scale.get("userIds", [])

            if not table_name or count == 0:
                continue

            uid = self.user_id
            if user_ids and uid not in user_ids:
                uid = user_ids[0]

            measurements = self.get_measurements(table_name, uid, count)
            all_measurements.extend(measurements)

        all_measurements.sort(
            key=lambda m: m.get("timeStamp", 0) or 0,
            reverse=True,
        )
        return all_measurements

    @staticmethod
    def _extract_records(page_data) -> list[dict] | None:
        """Extract measurement records from a page response."""
        if isinstance(page_data, list):
            return page_data if page_data else None

        if isinstance(page_data, dict):
            for key in ("list", "data", "records", "measurements"):
                if key in page_data and isinstance(page_data[key], list):
                    return page_data[key] if page_data[key] else None

            if "weight" in page_data:
                return [page_data]

        return None

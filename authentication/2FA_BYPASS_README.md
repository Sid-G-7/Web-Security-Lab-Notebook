# 2FA Bypass — PortSwigger Web Security Academy

## Overview

This project demonstrates an authentication weakness in a deliberately vulnerable PortSwigger Web Security Academy lab. It explores how an improperly protected multi-factor authentication (MFA) flow may allow automated testing of a four-digit verification code.

## Concepts demonstrated

- Multi-factor authentication (2FA/MFA)
- Session and cookie handling
- HTTP requests and redirect-based response checks
- Python threading and queues
- Authentication-flow testing

## Requirements

- Python 3.9 or later
- An authorized PortSwigger Web Security Academy lab
- The `requests` library

Install the dependency:

```bash
python -m pip install requests
```

## Configuration

Set the lab URL and your lab account credentials using environment variables.

**Linux/macOS:**

```bash
export LAB_URL="https://YOUR-ACTIVE-LAB-ID.web-security-academy.net"
export LAB_USERNAME="wiener"
export LAB_PASSWORD="YOUR-LAB-PASSWORD"
```

**Windows PowerShell:**

```powershell
$env:LAB_URL = "https://YOUR-ACTIVE-LAB-ID.web-security-academy.net"
$env:LAB_USERNAME = "wiener"
$env:LAB_PASSWORD = "YOUR-LAB-PASSWORD"
```

Use the URL and credentials for your own active lab. Do not commit credentials, cookies, or active lab identifiers to a public repository.

## Run

```bash
python 2FA_BYPASS.py
```

The script establishes a session, initiates the MFA flow, tests four-digit codes using worker threads, and checks the resulting account response.

## Important implementation notes

- The script expects the lab login to return an HTTP 302 redirect.
- A redirect from the MFA endpoint is treated as a candidate success; the account response is checked afterward.
- The account-content check is a basic heuristic and should not be treated as definitive proof by itself.
- TLS certificate verification is disabled in this lab demonstration. Do not use that setting for production systems or real user accounts.
- Concurrent requests and lab rate limits can affect results.

## Security takeaway

MFA verification endpoints should enforce attempt limits, expire verification codes, bind challenges to the correct user and session, and monitor repeated failures. A short code space should never be the only protection against automated guessing.

## Disclaimer

For educational purposes and authorized testing only. Use this script solely against your own PortSwigger Web Security Academy lab or another system for which you have explicit permission.

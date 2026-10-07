# Conditional Error-Based Blind SQL Injection — Binary Search

## Overview

This project demonstrates a conditional error-based blind SQL injection technique against an authorized PortSwigger Web Security Academy lab.

Unlike a traditional SQL injection where database output is directly returned in the HTTP response, this technique uses a deliberate database error as a boolean oracle.

The script first determines the password length and then extracts the password character-by-character using binary search.

---

## Objective

The objective of this lab was to understand how database errors can be intentionally triggered based on a SQL condition and then used to infer information that is not directly exposed by the application.

The manual Burp Suite workflow was converted into Python automation.

---

## Technique

This implementation combines:

* Conditional error-based SQL injection
* Blind SQL injection
* HTTP status-code analysis
* PostgreSQL SQL syntax
* ASCII character comparison
* Binary search
* Python Requests
* Burp Suite proxy integration

---

## Core Concept

The injected SQL condition is constructed so that:

```text
Condition TRUE
      ↓
1 / 0 executed
      ↓
Database error
      ↓
HTTP 500 response
```

while:

```text
Condition FALSE
      ↓
'a' returned
      ↓
No database error
      ↓
Normal HTTP response
```

Therefore:

```text
HTTP 500      → TRUE
Normal status → FALSE
```

The script converts this behavior into a boolean oracle.

---

## SQL Logic

The length-discovery phase conceptually tests:

```sql
LENGTH(password) > midpoint
```

The condition is embedded into a PostgreSQL `CASE` expression:

```sql
SELECT CASE
    WHEN LENGTH(password) > midpoint
    THEN TO_CHAR(1/0)
    ELSE 'a'
END
FROM users
WHERE username='administrator'
```

When the condition is TRUE, the deliberate division-by-zero causes an error.

The character extraction phase uses:

```sql
ASCII(
    SUBSTR(password, position, 1)
) > midpoint
```

This allows the script to determine the ASCII value of each character through repeated TRUE/FALSE comparisons.

---

## Binary Search

The script does not test every possible character sequentially.

It uses the following ordered character set:

```text
0123456789abcdefghijklmnopqrstuvwxyz
```

For each character:

```text
Start with complete search range
        ↓
Select midpoint
        ↓
Test ASCII(character) > midpoint
        ↓
TRUE  → search upper half
FALSE → search lower half
        ↓
Repeat
        ↓
Character identified
```

The same principle is applied to password-length discovery.

For a search space of `N` possible values, binary search requires approximately:

```text
O(log2(N))
```

comparisons in the ideal case.

---

## Two-Phase Workflow

### Phase 1 — Password Length

The script searches between:

```text
MIN_LENGTH = 1
MAX_LENGTH = 64
```

using binary search.

Example:

```text
Is password length > 32?
        ↓
TRUE / FALSE
        ↓
Reduce search range

Is password length > 48?
        ↓
TRUE / FALSE
        ↓
Reduce search range

...
```

Eventually the exact length is identified.

### Phase 2 — Password Characters

Once the length is known, the script processes:

```text
position = 1
position = 2
position = 3
...
```

For every position, it performs ASCII comparisons and binary search until a character is identified.

---

## Burp Suite Workflow

The technique can be validated manually before automation.

### Step 1

Capture the application request using Burp Suite.

### Step 2

Identify the parameter or cookie that reaches the SQL query.

### Step 3

Send the request to Repeater.

### Step 4

Establish the difference between a normal response and the intentional database error.

### Step 5

Confirm that the TRUE condition consistently produces:

```text
HTTP 500
```

### Step 6

Automate the same behavior with Python.

The script sends requests through:

```text
127.0.0.1:8080
```

so the traffic can be inspected in Burp Suite while the automation runs.

---

## Python Structure

### `validate_configuration()`

Checks that required runtime configuration is available before the attack workflow starts.

### `is_true_response()`

Acts as the SQL injection oracle.

For this lab:

```python
return response.status_code == 500
```

### `send_tracking_id()`

Sends the crafted request using the configured TrackingId and session cookie.

### `find_password_length()`

Uses binary search to determine the target password length.

### `test_character_greater_than()`

Tests whether the ASCII value of a specific password character is greater than the selected midpoint.

### `find_character()`

Performs binary search over the configured character set.

### `find_password()`

Iterates over all password positions and constructs the final result.

---

## Configuration

The following lab-specific values are supplied through environment variables instead of being committed to GitHub:

```text
LAB_URL
LAB_SESSION
TRACKING_PREFIX
```

Example:

```bash
export LAB_URL="https://YOUR-LAB.web-security-academy.net/filter"
export LAB_SESSION="YOUR_CURRENT_SESSION"
export TRACKING_PREFIX="YOUR_TRACKING_PREFIX"
```

Then run:

```bash
python SQLi_Conditional_Based_Errors_BINARY_SEARCH2.py
```

### Why use environment variables?

PortSwigger lab sessions are temporary and lab-specific.

Keeping the target URL, session cookie, and TrackingId prefix outside the source code:

* prevents accidental publication of session information
* makes the script reusable for a different lab instance
* separates configuration from implementation
* demonstrates better security engineering practices

---

## Burp Suite Proxy

The script uses:

```text
HTTP  → 127.0.0.1:8080
HTTPS → 127.0.0.1:8080
```

This is the standard local Burp Suite proxy configuration.

Requests can therefore be observed in:

```text
Proxy → HTTP history
```

or sent through Burp Repeater during manual validation.

---

## TLS Verification

The original lab script disabled TLS verification.

The portfolio version preserves that default behavior to avoid changing the original Burp-based workflow:

```text
VERIFY_TLS=false
```

For environments where the Burp CA certificate is properly trusted, verification can be enabled:

```bash
export VERIFY_TLS=true
```

---

## Example Output

The script reports the binary-search decisions during execution.

Example structure:

```text
======================================================================
[*] Finding password length
======================================================================
[>] LENGTH(password) > 32 => TRUE (HTTP 500)
[>] LENGTH(password) > 48 => FALSE (HTTP 200)
...

======================================================================
[*] Extracting administrator password
[*] Length = 20
======================================================================

----------------------------------------------------------------------
[*] Finding character at position 1
----------------------------------------------------------------------
[>] ASCII(password[1]) > 109 ('m') => TRUE
[>] ASCII(password[1]) > 115 ('s') => FALSE
...
[+] Position 1 = 'p'
```

The exact values depend on the current authorized lab instance.

---

## Key Learning Outcomes

This lab helped me understand:

* Conditional error-based SQL injection.
* Blind SQL injection through indirect application behavior.
* How database errors can act as information oracles.
* PostgreSQL `CASE` expressions.
* Division-by-zero as a deliberate error condition.
* HTTP status codes as a detection mechanism.
* Binary search for efficient inference.
* Character-by-character data extraction.
* Burp Suite request analysis.
* Python HTTP automation.
* Separation of sensitive configuration from source code.

---

## Comparison With Boolean Response-Based Blind SQLi

The previous blind SQLi implementation used a response-content indicator.

This implementation uses a database error instead.

```text
Boolean response-based SQLi
        ↓
Inspect response body
        ↓
TRUE / FALSE
```

versus:

```text
Conditional error-based SQLi
        ↓
Trigger database error
        ↓
Inspect HTTP status
        ↓
TRUE / FALSE
```

Both techniques demonstrate the same broader concept:

> Convert observable application behavior into a boolean oracle and use that oracle to infer data.

---

## Limitations

This script is intentionally tailored to the behavior of the target lab.

It assumes:

* PostgreSQL-compatible syntax.
* A `users` table.
* An `administrator` username.
* A `password` column.
* The `TrackingId` cookie as the injection point.
* HTTP 500 as the TRUE indicator.
* Digits and lowercase letters as the expected password character set.
* A password length within the configured range.

These assumptions may need to be changed for another lab or authorized application.

---

## Security Notice

This project is intended only for authorized security testing and educational environments, including:

* PortSwigger Web Security Academy.
* CTF environments.
* Intentionally vulnerable applications.
* Systems where explicit authorization has been provided.

Do not use this technique against systems without permission.

---

## Technologies

```text
Python
Requests
Burp Suite
PortSwigger Web Security Academy
Git / GitHub
```

---

## Portfolio Context

This lab is part of my ongoing web application security learning journey.

The broader repository documents the progression from:

```text
Manual Burp Suite Testing
        ↓
Understanding the Vulnerability
        ↓
Python Automation
        ↓
Algorithm Optimization
        ↓
Reusable Security Tooling
```

This particular lab demonstrates the use of a conditional database error as an oracle and the application of binary search to make blind SQL injection inference more efficient.

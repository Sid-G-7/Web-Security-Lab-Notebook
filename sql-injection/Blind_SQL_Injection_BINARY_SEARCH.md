# Blind SQL Injection — Binary Search

## Overview

This project demonstrates automation of a blind SQL injection technique against an authorized PortSwigger Web Security Academy lab.

The application does not directly disclose the target password. Instead, the script constructs a boolean SQL condition and determines whether the condition is true or false by observing the application's response.

The resulting TRUE/FALSE oracle is combined with binary search to efficiently determine each character.

---

## Objective

The objective of this lab was to understand how a blind SQL injection can be:

1. Identified manually using Burp Suite.
2. Converted into a reliable boolean oracle.
3. Automated with Python.
4. Optimized using binary search.

This exercise demonstrates the transition from manual web application security testing to repeatable automation.

---

## Vulnerability

Blind SQL injection occurs when user-controlled input reaches a SQL query but the application does not directly return the queried database value.

Instead, the tester can infer information from differences in application behavior.

In this lab, the response contains:

```text
Welcome back
```

when the injected SQL condition evaluates to TRUE.

This response therefore becomes the boolean oracle used by the script.

---

## SQL Injection Logic

The script builds a TrackingId value containing a condition conceptually equivalent to:

```sql
' AND (
    SELECT ASCII(
        SUBSTRING(password, position, 1)
    )
    FROM users
    WHERE username='administrator'
) > ascii_value--
```

The database evaluates the condition and the web application responds differently depending on whether it is TRUE or FALSE.

The Python script checks for:

```python
"Welcome back" in response.text
```

and converts the result into a Python boolean.

---

## Binary Search

Instead of testing every possible character one at a time, the script uses binary search.

The character set is:

```text
0123456789abcdefghijklmnopqrstuvwxyz
```

For each password position:

```text
Start with full character range
        ↓
Choose midpoint
        ↓
Test ASCII(character) > midpoint
        ↓
TRUE  → search upper half
FALSE → search lower half
        ↓
Repeat
        ↓
Identify character
```

This reduces the number of comparisons required for each character.

For a character set of approximately 36 possible values:

```text
Linear search:
up to ~36 comparisons

Binary search:
approximately ~6 comparisons
```

---

## Python Implementation

The script uses:

### `requests.Session`

Maintains HTTP session behavior and reuses the underlying connection.

### Burp Suite Proxy

Requests are routed through:

```text
127.0.0.1:8080
```

allowing the traffic to be inspected in Burp Suite.

### `test_condition()`

Builds and sends the SQL injection condition and determines whether the application response represents TRUE or FALSE.

### `find_character()`

Uses binary search to determine one character from the configured character set.

### `main()`

Iterates through the configured password length and combines the recovered characters.

---

## Configuration

Sensitive lab-specific values are intentionally not hard-coded into the public source code.

The script reads the following environment variables:

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

Then:

```bash
python Blind_SQL_Injection_BINARY_SEARCH.py
```

### Why this approach?

Hard-coding authentication/session information in a public GitHub repository creates an unnecessary security risk.

Separating configuration from source code makes the script reusable across lab instances while preventing sensitive values from being committed.

---

## Burp Suite Integration

The script routes HTTP and HTTPS requests through the local Burp Suite proxy:

```text
127.0.0.1:8080
```

This provides visibility into:

* HTTP requests
* Query parameters
* Cookies
* SQL injection payloads
* HTTP responses
* Response differences

A practical workflow is:

```text
PortSwigger Lab
      ↓
Burp Suite
      ↓
Understand request
      ↓
Identify injectable input
      ↓
Test SQL condition manually
      ↓
Confirm TRUE/FALSE behavior
      ↓
Automate with Python
```

---

## Lab Workflow

### 1. Understand the application

First, interact with the lab normally and observe how requests are generated.

### 2. Capture the request

Use Burp Suite Proxy/HTTP history to inspect the request.

### 3. Identify the injection point

Determine which value is incorporated into the application's SQL query.

### 4. Establish the boolean oracle

Test TRUE and FALSE SQL conditions and compare application behavior.

### 5. Automate

Use Python Requests to send the same request repeatedly with different conditions.

### 6. Optimize

Replace sequential character testing with binary search.

### 7. Verify

Confirm that the final extracted value satisfies the lab's objective.

---

## Example Output

The script displays the binary-search decisions while testing each position.

Example:

```text
============================================================
[*] Extracting position 1
============================================================
[>] position=1 test='i' ASCII=105 range=0-35 => TRUE
[>] position=1 test='s' ASCII=115 range=18-35 => FALSE
[>] position=1 test='n' ASCII=110 range=18-26 => FALSE
...
[+] Position 1 = 'p'
```

The exact output depends on the current authorized lab instance.

Sensitive session values are never stored in the public source code.

---

## Key Learning Outcomes

This lab helped me understand:

* Blind SQL injection fundamentals.
* Boolean-based inference.
* Response-based SQL injection oracles.
* ASCII comparison techniques.
* Character-by-character extraction.
* Binary-search optimization.
* HTTP session management with Python Requests.
* Burp Suite-assisted web security testing.
* Separating configuration/secrets from application logic.
* Turning a manual testing technique into repeatable automation.

---

## Why Binary Search Matters

Security automation can become inefficient when every possible value is tested sequentially.

Binary search reduces the search space by approximately half after each comparison.

For a search space of `N` values, binary search requires approximately:

```text
O(log2(N))
```

comparisons in the ideal case.

This makes the technique particularly useful when each comparison requires an HTTP request.

---

## Limitations

This implementation is intentionally tailored to the lab's known behavior.

It assumes:

* PostgreSQL-compatible SQL syntax.
* A `users` table.
* An `administrator` username.
* A `password` column.
* The `TrackingId` cookie as the injection point.
* `"Welcome back"` as the TRUE response indicator.
* A 20-character target password.
* Lowercase letters and digits as the expected character set.

These assumptions must be adapted for a different lab or authorized application.

---

## Security Notice

This project is intended for authorized security testing and educational environments, including:

* PortSwigger Web Security Academy.
* CTF environments.
* Intentionally vulnerable applications.
* Systems where explicit authorization has been provided.

Do not use the technique against systems without permission.

---

## Technology

```text
Python
Requests
Burp Suite
PortSwigger Web Security Academy
Git / GitHub
```

## Project Type

Educational web application security automation.

## Author Notes

This lab is part of my ongoing hands-on study of web application security. I am documenting both the manual Burp Suite methodology and the Python automation used to make repeatable testing more efficient.

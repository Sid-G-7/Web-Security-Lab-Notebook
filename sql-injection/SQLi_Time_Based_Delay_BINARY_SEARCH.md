# Time-Based Blind SQL Injection — Binary Search

## Overview

This project demonstrates automation of a time-based blind SQL injection technique against an authorized PortSwigger Web Security Academy lab.

Unlike an injection where the application visibly returns database errors or queried data, this technique uses the amount of time taken to respond as a boolean oracle.

A condition that evaluates to TRUE causes PostgreSQL to execute:

```sql
pg_sleep(3)
```

while a FALSE condition executes:

```sql
pg_sleep(0)
```

The Python script measures the HTTP response time and converts the delay into a TRUE/FALSE result.

Binary search is then used to determine the password length and individual password characters efficiently.

---

## Objective

The objective of this lab was to understand how response timing can be used to infer information from a database when the application does not directly reveal the queried value.

The manual Burp Suite testing process was converted into Python automation.

---

## Technique

This implementation combines:

* Time-based blind SQL injection
* PostgreSQL `pg_sleep()`
* Response-time analysis
* Boolean inference
* Character-by-character extraction
* Binary search
* Python Requests
* Burp Suite proxy integration

---

## Core Concept

The SQL logic intentionally introduces a delay when a condition evaluates to TRUE.

Conceptually:

```text
Condition TRUE
      ↓
pg_sleep(3)
      ↓
Delayed HTTP response
      ↓
TRUE
```

while:

```text
Condition FALSE
      ↓
pg_sleep(0)
      ↓
Normal response time
      ↓
FALSE
```

The script measures the elapsed time for each request.

---

## Timing Oracle

The script uses:

```python
TRUE_THRESHOLD = 2.0
```

The intended behavior is:

```text
Elapsed time >= 2 seconds
        ↓
TRUE

Elapsed time < 2 seconds
        ↓
FALSE
```

The threshold is intentionally below the 3-second PostgreSQL delay to provide a margin for normal network/application overhead.

---

## SQL Injection Logic

The password-length condition is conceptually:

```sql
LENGTH(password) > midpoint
```

and is embedded in a PostgreSQL expression equivalent to:

```sql
SELECT CASE
    WHEN LENGTH(password) > midpoint
    THEN pg_sleep(3)
    ELSE pg_sleep(0)
END
FROM users
WHERE username='administrator'
```

For character extraction, the script compares a character from the password against a midpoint character:

```sql
SUBSTRING(password, position, 1) > 'midpoint'
```

The result determines whether the binary-search range should move upward or downward.

---

## Binary Search

The character set used by the script is:

```text
0123456789abcdefghijklmnopqrstuvwxyz
```

For each password position:

```text
Start with complete character range
        ↓
Select midpoint character
        ↓
Compare target character with midpoint
        ↓
Measure response time
        ↓
TRUE  → search upper half
FALSE → search lower half
        ↓
Repeat
        ↓
Character identified
```

This avoids testing every candidate sequentially.

For a search space containing approximately 36 characters:

```text
Linear search:
up to ~36 comparisons

Binary search:
approximately ~6 comparisons
```

---

## Two-Phase Extraction

### Phase 1 — Determine Password Length

The script first searches for the password length between:

```text
MIN_LENGTH = 1
MAX_LENGTH = 64
```

It tests conditions such as:

```text
LENGTH(password) > 32
LENGTH(password) > 48
LENGTH(password) > 40
...
```

Each request is classified using response time.

Binary search then converges on the exact length.

### Phase 2 — Extract Password Characters

Once the length is known, the script processes:

```text
position 1
position 2
position 3
...
```

At every position, it performs character comparisons using the time-based oracle.

---

## Burp Suite Workflow

Before automation, the injection behavior can be tested manually in Burp Suite.

### 1. Intercept the request

Use Burp Suite Proxy to capture the authorized lab request.

### 2. Send to Repeater

This makes it easier to compare different TrackingId values.

### 3. Establish the timing difference

Test a condition designed to cause:

```text
pg_sleep(3)
```

and compare it with a condition that executes:

```text
pg_sleep(0)
```

### 4. Confirm the oracle

Verify that TRUE and FALSE conditions produce a reliable difference in response time.

### 5. Automate

Use the Python script to repeat the requests and perform binary search.

Requests are routed through:

```text
127.0.0.1:8080
```

so they can be inspected in Burp Suite.

---

## Python Implementation

### `send_request()`

Sends the HTTP request and measures elapsed time using:

```python
time.perf_counter()
```

This provides a high-resolution timer suitable for measuring response delays.

### `is_true()`

Converts elapsed time into a boolean result:

```python
return elapsed >= TRUE_THRESHOLD
```

### `find_password_length()`

Uses binary search to determine the target password length.

### `test_character_greater_than()`

Tests whether the target password character is greater than the selected midpoint character.

### `find_character()`

Performs binary search over the configured character set.

### `find_password()`

Iterates through all positions and builds the recovered value.

### `main()`

Coordinates configuration, password-length discovery, character extraction, and result reporting.

---

## Configuration

Lab-specific values are intentionally loaded from environment variables rather than stored in the source code.

Required variables:

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
python SQLi_Time_Based_Delay_BINARY_SEARCH.py
```

### Why use environment variables?

PortSwigger lab instances use temporary, lab-specific session information.

Separating configuration from source code:

* prevents accidental publication of session information
* allows the script to work with a new lab instance
* keeps sensitive values out of Git history
* demonstrates better security engineering practices

---

## Burp Suite Proxy

The script is configured to send traffic through:

```text
HTTP  → 127.0.0.1:8080
HTTPS → 127.0.0.1:8080
```

This enables inspection of:

* HTTP requests
* Cookies
* TrackingId values
* SQL injection payloads
* HTTP responses
* Response timing

---

## TLS Verification

The original implementation used:

```python
verify=False
```

The portfolio version preserves the same default behavior so that the existing Burp Suite workflow is not changed.

By default:

```text
VERIFY_TLS=false
```

For an environment where the appropriate Burp CA certificate is trusted, TLS verification can be enabled:

```bash
export VERIFY_TLS=true
```

---

## Example Output

The script records the measured response time for each test.

Example:

```text
======================================================================
[*] Finding password length
======================================================================
[>] LENGTH(password) > 32 | 3.04s | TRUE
[>] LENGTH(password) > 48 | 0.18s | FALSE
[>] LENGTH(password) > 40 | 3.01s | TRUE
...
[+] Password length = 20
```

Character extraction follows the same process:

```text
----------------------------------------------------------------------
[*] Finding character at position 1
----------------------------------------------------------------------
[>] password[1] > 'h' | 3.02s | TRUE | range=0-35
[>] password[1] > 'r' | 0.19s | FALSE | range=18-35
...
[+] Position 1 = 'p'
```

The exact timings depend on the current lab instance and network conditions.

---

## Important Timing Consideration

Unlike a response-content oracle, a time-based oracle can be affected by:

* network latency
* proxy overhead
* server load
* temporary application delays
* inconsistent response times

Therefore, the threshold must be chosen carefully.

This implementation uses:

```text
pg_sleep(3)
TRUE_THRESHOLD = 2.0 seconds
```

The threshold is deliberately below the expected 3-second delay.

---

## Key Learning Outcomes

This lab helped me understand:

* Time-based blind SQL injection.
* PostgreSQL `pg_sleep()`.
* Using response timing as a boolean oracle.
* Character-by-character inference.
* Binary-search optimization.
* Measuring HTTP latency with Python.
* Burp Suite proxy-based request inspection.
* Automating repetitive security-testing workflows.
* The effect of network/application latency on timing-based detection.
* The importance of keeping lab credentials and session data out of source control.

---

## Comparison With Other Blind SQLi Techniques

This repository contains multiple approaches to blind SQL injection.

### Boolean / Response-Based

```text
SQL condition
      ↓
Application response
      ↓
TRUE / FALSE
```

### Conditional Error-Based

```text
SQL condition
      ↓
Database error or no error
      ↓
HTTP behavior
      ↓
TRUE / FALSE
```

### Time-Based

```text
SQL condition
      ↓
pg_sleep(3) / pg_sleep(0)
      ↓
Response timing
      ↓
TRUE / FALSE
```

The common principle is:

> Turn observable application behavior into a boolean oracle, then use that oracle to infer information.

---

## Limitations

This script is intentionally tailored to the behavior of the PortSwigger lab.

It assumes:

* PostgreSQL-compatible SQL syntax.
* A `users` table.
* An `administrator` username.
* A `password` column.
* The `TrackingId` cookie as the injection point.
* `pg_sleep()` as the timing mechanism.
* Approximately 3 seconds for a TRUE condition.
* A 2-second TRUE threshold.
* Digits and lowercase letters as the expected character set.
* A password length within the configured range.

These assumptions will not necessarily apply to another application or lab.

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
PostgreSQL SQL Syntax
Burp Suite
PortSwigger Web Security Academy
Git / GitHub
```

---

## Portfolio Context

This lab is part of my hands-on web application security learning journey.

The progression demonstrated by these SQL injection labs is:

```text
Manual Burp Suite Testing
        ↓
Understand the SQL Injection Behavior
        ↓
Build a Boolean Oracle
        ↓
Automate HTTP Requests
        ↓
Optimize With Binary Search
        ↓
Document the Technique
```

This particular implementation demonstrates how response timing can be converted into a reliable inference mechanism for blind SQL injection testing.

# Unified SQL Injection Lab Automation

## Overview

This project demonstrates a Python-based approach to automating SQL injection testing in authorized PortSwigger Web Security Academy labs.

It brings together three SQL injection techniques:

* Time-based blind SQL injection
* Conditional error-based SQL injection
* Boolean-based blind SQL injection

The program checks whether each supported technique appears to work, selects a method according to its configured priority, and uses binary search to infer the password length and individual characters.

This project builds on my earlier lab scripts by bringing multiple testing approaches into one class-based implementation.

## Objectives

* Understand differences between common blind SQL injection techniques.
* Convert observable HTTP responses into TRUE/FALSE decisions.
* Reuse common request-handling and extraction logic.
* Apply binary search to reduce the number of comparisons.
* Integrate Python Requests with the Burp Suite proxy.
* Separate lab configuration from the implementation.

## Architecture

```text
Runtime Configuration
        |
        v
HTTP Session and Proxy
        |
        v
SQLi Method Detection
        |
        v
Select Supported Method
        |
        v
Build Method-Specific Payload
        |
        v
Determine Password Length
        |
        v
Binary Search for Each Character
        |
        v
Display Result
```

## Supported Techniques

### 1. Time-Based Blind SQL Injection

The script uses PostgreSQL `pg_sleep()` payloads and measures response time.

The configured threshold is used to distinguish delayed responses from normal responses.

### 2. Conditional Error-Based SQL Injection

The script attempts to trigger a database error for a TRUE condition and uses HTTP status code 500 as an indicator.

### 3. Boolean-Based Blind SQL Injection

The script checks for the expected response marker, `Welcome back`, to distinguish the lab's TRUE condition.

These response indicators are specific to the assumed lab behavior. A different application may require different indicators.

## Automatic Method Detection

The program tests the supported methods and prioritizes them in the following order:

1. Time-based
2. Error-based
3. Boolean-based

If no supported method is detected, it stops rather than attempting password extraction.

Detection is heuristic. A response status or timing difference alone does not prove SQL injection, so results should be verified manually in Burp Suite.

## Binary Search

After selecting a method, the script first determines the password length and then tests each character position.

The default character set is:

```text
0123456789abcdefghijklmnopqrstuvwxyz
```

Conceptually, each comparison narrows the possible values:

```text
Initial search range
        |
        v
Choose midpoint
        |
        v
Evaluate SQL condition
        |
        v
Interpret response
        |
        v
Keep one half of the range
        |
        v
Repeat until the value is identified
```

For a search space of N ordered values, binary search takes approximately O(log₂ N) comparisons in the ideal case.

## Implementation Details

### `Config`

Stores runtime configuration, character-set defaults, password-length bounds, timing settings, and proxy configuration.

### `SQLiExtractor`

Coordinates HTTP requests, method detection, payload construction, and extraction.

### `send_request()`

Sends an HTTP request and measures its elapsed time.

### `auto_detect_method()`

Tests the three supported methods and selects one based on the predefined priority.

### Payload builders

Separate functions construct payloads for each method and for password-length and character comparisons.

### `find_password_length()`

Uses binary search to narrow down the candidate password length.

### `find_character()`

Uses binary search over the configured character set to infer one character at a time.

### `extract_password()`

Processes each password position and combines the inferred characters.

## Requirements

* Python 3
* Requests
* Burp Suite, optional but recommended for traffic inspection
* An authorized PortSwigger Web Security Academy lab or equivalent intentionally vulnerable environment

Install the dependency:

```bash
python -m pip install requests
```

## Usage

Run the script:

```bash
python UNIFIED_13_TRIM.py
```

It prompts for:

* The authorized lab URL
* The current lab session cookie
* The TrackingId prefix
* Optional custom character set and password-length bounds

The session cookie is entered without echoing it to the terminal.

Do not commit session cookies, authentication values, or other secrets to GitHub.

## Burp Suite Integration

The default proxy is:

```text
127.0.0.1:8080
```

This allows requests to be inspected in Burp Suite Proxy HTTP history.

A useful workflow is to verify the behavior manually in Repeater first, then run the automation and compare the resulting requests and responses.

## Limitations

This implementation is designed around specific lab assumptions:

* A `TrackingId` cookie as the injection point
* A `users` table
* An `administrator` record
* A `password` field
* A response containing `Welcome back` for the boolean indicator
* Particular database-specific error and timing payloads
* A configured character set and password-length range

The supported payloads do not work across every database engine. Timing measurements can also be affected by network latency, server load, and proxy overhead.

This is an educational lab script, not a general-purpose production scanner.

## Key Learning Outcomes

Through this project, I explored:

* Multiple blind SQL injection approaches.
* Response-content and HTTP-status oracles.
* Timing-based inference.
* Binary-search optimization.
* Reusable Python classes and methods.
* Method-specific payload builders.
* HTTP session handling and proxy configuration.
* Manual validation of automated security-testing results.

## Security Notice

This project is intended for authorized security testing in PortSwigger Web Security Academy labs, CTF environments, local vulnerable applications, and other environments where explicit permission has been granted.

Do not use it against systems without authorization.

## Project Context

This project represents the next step in my web security learning journey:

**Individual SQLi scripts → Multiple detection techniques → Unified automation → Reusable security-testing components.**

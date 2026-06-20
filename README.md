# Phishing URL Detector

## Overview

Phishing URL Detector is a Python-based cybersecurity project that analyzes URLs and identifies potential phishing indicators.

## Features

- Detects IP-based URLs
- Detects suspicious keywords
- Detects excessive subdomains
- Detects URL shorteners
- Detects suspicious TLDs
- Calculates risk score
- Provides risk level classification

## Technologies Used

- Python
- Regular Expressions (re)
- urllib.parse

## Example

Input:

https://secure-login-update-bank.tk

Output:

Risk Score : 8
Risk Level : HIGH RISK

Detected Issues:
- Contains suspicious keyword: login
- Contains suspicious keyword: secure
- Suspicious TLD detected: .tk

## Future Improvements

- Machine Learning based detection
- Real-time URL reputation checking
- GUI interface

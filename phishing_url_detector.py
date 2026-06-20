import re
from urllib.parse import urlparse

print("=" * 50)
print("PHISHING URL DETECTOR")
print("=" * 50)

url = input("\nEnter URL: ").strip()

risk_score = 0
issues = []

try:
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Check for IP address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        risk_score += 3
        issues.append("Uses an IP address instead of a domain name")

    # Check suspicious keywords
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "password",
        "banking"
    ]

    for word in suspicious_words:
        if word in url.lower():
            risk_score += 2
            issues.append(f"Contains suspicious keyword: {word}")

    # Check URL length
    if len(url) > 100:
        risk_score += 2
        issues.append("URL is unusually long")

    # Check hyphens
    if domain.count("-") > 2:
        risk_score += 2
        issues.append("Too many hyphens in domain")

    # Check subdomains
    if domain.count(".") > 3:
        risk_score += 2
        issues.append("Too many subdomains")

    # Check @ symbol
    if "@" in url:
        risk_score += 3
        issues.append("Contains @ symbol")

    # Check URL shorteners
    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "shorturl.at",
        "goo.gl"
    ]

    for site in shorteners:
        if site in url.lower():
            risk_score += 2
            issues.append("Uses URL shortening service")

    # Check suspicious TLDs
    suspicious_tlds = ["tk", "ml", "ga", "cf", "gq"]

    if "." in domain:
        tld = domain.split(".")[-1]

        if tld in suspicious_tlds:
            risk_score += 2
            issues.append(f"Suspicious TLD detected: .{tld}")

except:
    print("Invalid URL")
    exit()

# Risk Level
if risk_score == 0:
    risk_level = "SAFE"
elif risk_score <= 3:
    risk_level = "LOW RISK"
elif risk_score <= 6:
    risk_level = "MEDIUM RISK"
else:
    risk_level = "HIGH RISK"

print("\n" + "-" * 40)
print("SCAN RESULT")
print("-" * 40)

print(f"Risk Score : {risk_score}")
print(f"Risk Level : {risk_level}")

if risk_level == "HIGH RISK":
    print("\n⚠ WARNING: This URL appears suspicious.")
elif risk_level == "MEDIUM RISK":
    print("\n⚡ Use caution before visiting.")
else:
    print("\n✓ No major phishing indicators found.")

print("\nDetected Issues:")

if issues:
    for issue in issues:
        print(f"- {issue}")
else:
    print("- No suspicious indicators detected.")

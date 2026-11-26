#!/usr/bin/env python3
"""
Password Strength Checker
-------------------------
A small, dependency-free Python tool that analyses a password and reports:

  * a strength score (0-100) and rating (Very Weak -> Excellent)
  * an entropy estimate (in bits)
  * a rough "time to crack" estimate for an offline attack
  * practical, human-readable tips to make the password stronger

The password is checked locally on your own machine only.
Nothing is sent over the network and nothing is stored.

Author: Qamar Iqbal (Cyber Security Student)
Usage:
    python password_strength.py              # interactive prompt
    python password_strength.py "MyPass123"  # check one password directly
"""

import math
import re
import sys
import getpass

# A tiny built-in list of very common passwords. Real-world tools use much
# larger leaked-password lists; this is enough to demonstrate the idea.
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345", "12345678", "qwerty",
    "1234567", "111111", "1234567890", "123123", "abc123", "1234",
    "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123",
    "zaq12wsx", "dragon", "sunshine", "princess", "letmein",
    "654321", "monkey", "27653", "1qaz2wsx", "123321", "qwertyuiop",
    "superman", "asdfghjkl", "football", "charlie", "admin",
    "welcome", "login", "passw0rd", "shadow", "master",
    "pakistan", "pakistan123", "786786", "allah", "computer",
}

# Average guesses per second for a modern offline cracking rig (bcrypt aside,
# fast hashes like MD5/SHA1 can be attacked at billions of guesses/second).
OFFLINE_GUESSES_PER_SECOND = 10_000_000_000  # 10 billion / second


def analyse(password: str) -> dict:
    """Analyse a password and return a dictionary of results."""
    checks = {
        "length": len(password),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", password)),
        "common": password.lower() in COMMON_PASSWORDS,
        "repeat_run": bool(re.search(r"(.)\1{2,}", password)),
        "sequence": bool(re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password.lower())),
    }

    # ---- character pool size (used for the entropy estimate) -------------
    pool = 0
    if checks["lowercase"]:
        pool += 26
    if checks["uppercase"]:
        pool += 26
    if checks["digits"]:
        pool += 10
    if checks["symbols"]:
        pool += 33

    entropy = len(password) * math.log2(pool) if pool else 0.0

    # ---- score (0-100) ----------------------------------------------------
    score = 0
    score += min(len(password), 20) * 2                      # up to 40 pts
    score += sum([checks["lowercase"], checks["uppercase"],
                  checks["digits"], checks["symbols"]]) * 10  # up to 40 pts
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    if checks["common"]:
        score = min(score, 5)
    if checks["repeat_run"]:
        score -= 10
    if checks["sequence"]:
        score -= 10
    score = max(0, min(100, score))

    if score < 20:
        rating = "Very Weak"
    elif score < 40:
        rating = "Weak"
    elif score < 60:
        rating = "Fair"
    elif score < 80:
        rating = "Strong"
    else:
        rating = "Excellent"

    # ---- crack-time estimate (average case = half the keyspace) ----------
    seconds = (2 ** entropy) / OFFLINE_GUESSES_PER_SECOND / 2 if entropy else 0
    crack_time = human_time(seconds)

    # ---- tips --------------------------------------------------------------
    tips = []
    if checks["common"]:
        tips.append("This password appears in common-password lists. Never use it anywhere.")
    if len(password) < 12:
        tips.append("Make it longer: aim for at least 12-16 characters. Length beats complexity.")
    if not checks["uppercase"]:
        tips.append("Add some UPPERCASE letters.")
    if not checks["lowercase"]:
        tips.append("Add some lowercase letters.")
    if not checks["digits"]:
        tips.append("Add a few numbers.")
    if not checks["symbols"]:
        tips.append("Add symbols such as ! @ # $ % to widen the character pool.")
    if checks["repeat_run"]:
        tips.append("Avoid repeated characters such as 'aaa' or '111'.")
    if checks["sequence"]:
        tips.append("Avoid sequences such as '123' or 'abc' - they are guessed early.")
    if not tips:
        tips.append("Great password habits! Now store it in a password manager and "
                    "never reuse it on another site.")

    return {
        "checks": checks,
        "entropy": round(entropy, 1),
        "score": score,
        "rating": rating,
        "crack_time": crack_time,
        "tips": tips,
    }


def human_time(seconds: float) -> str:
    """Turn a number of seconds into a friendly string."""
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return f"{seconds:.0f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.0f} days"
    if seconds < 31_536_000 * 1000:
        return f"{seconds / 31_536_000:.0f} years"
    if seconds < 31_536_000 * 1_000_000:
        return f"{seconds / 31_536_000 / 1000:,.0f} thousand years"
    return "millions of years"


def bar(score: int, width: int = 25) -> str:
    filled = round(score / 100 * width)
    return "#" * filled + "-" * (width - filled)


def report(password: str) -> None:
    r = analyse(password)
    c = r["checks"]
    print("\n================ PASSWORD REPORT ================")
    print(f" Length          : {c['length']} characters")
    print(f" Lowercase       : {'yes' if c['lowercase'] else 'no'}")
    print(f" Uppercase       : {'yes' if c['uppercase'] else 'no'}")
    print(f" Digits          : {'yes' if c['digits'] else 'no'}")
    print(f" Symbols         : {'yes' if c['symbols'] else 'no'}")
    print(f" Entropy         : ~{r['entropy']} bits")
    print(f" Score           : {r['score']}/100  [{bar(r['score'])}]  {r['rating']}")
    print(f" Est. crack time : {r['crack_time']} (offline attack, fast hash)")
    print("-------------------------------------------------")
    print(" Tips:")
    for tip in r["tips"]:
        print(f"  - {tip}")
    print("=================================================\n")


def main() -> None:
    print("Password Strength Checker - by Qamar Iqbal")
    print("Your password never leaves this machine.\n")
    if len(sys.argv) > 1:
        report(sys.argv[1])
    else:
        while True:
            pw = getpass.getpass("Enter a password to check (blank to quit): ")
            if not pw:
                break
            report(pw)


if __name__ == "__main__":
    main()

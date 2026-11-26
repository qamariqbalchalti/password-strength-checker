# 🔐 Password Strength Checker

A small, dependency-free **Python** tool that analyses a password and tells you — in plain language — how strong it really is, how long a modern cracking rig would take to break it, and exactly what to fix.

Built as a learning project by **Qamar Iqbal**, Cyber Security student at COMSATS University Islamabad, as part of my daily cyber-security practice. I share one practical security tip every day on [LinkedIn](https://www.linkedin.com/in/qamar-iqbal-chalti/) — this tool is the hands-on companion to the password tips.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## ✨ What it checks

- **Length** and character variety (lowercase, UPPERCASE, digits, symbols)
- **Entropy estimate** in bits, based on the character pool
- **Estimated crack time** for an offline attack at 10 billion guesses/second
- **Common-password detection** against a built-in list of widely leaked passwords
- **Bad patterns** — repeated characters (`aaa`, `111`) and sequences (`123`, `abc`)
- A **0–100 score** with a rating from *Very Weak* to *Excellent*, plus clear tips

## 🚀 How to run

No installation, no libraries — just Python 3.8 or newer.

```bash
# Interactive mode (input is hidden while you type)
python password_strength.py

# Check one password directly
python password_strength.py "MyPass123"
```

## 📸 Example output

```
================ PASSWORD REPORT ================
 Length          : 9 characters
 Lowercase       : yes
 Uppercase       : yes
 Digits          : yes
 Symbols         : no
 Entropy         : ~53.6 bits
 Score           : 38/100  [##########---------------]  Weak
 Est. crack time : 8 days (offline attack, fast hash)
-------------------------------------------------
 Tips:
  - Make it longer: aim for at least 12-16 characters. Length beats complexity.
  - Add symbols such as ! @ # $ % to widen the character pool.
  - Avoid sequences such as '123' or 'abc' - they are guessed early.
=================================================
```

## 🧠 What I learned building this

- Why **length beats complexity** — every extra character multiplies the search space
- How **entropy** (bits) translates into real crack time
- Why password reuse and common passwords are the #1 way accounts get taken over
- The habits that actually fix it: long passphrases, a **password manager**, and **two-factor authentication (2FA)** on every important account

## ⚠️ Note

The crack-time figure is an educational estimate for a fast-hash offline attack. Real-world safety also depends on how a website stores passwords (slow hashes like bcrypt/Argon2 help a lot) and on 2FA. This tool runs **100% locally** — your password is never sent anywhere or saved.

## 📄 License

MIT — free to use, learn from, and improve.

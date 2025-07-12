# 🛡️ Beacon: OWASP Security Misconfiguration Scanner

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Platform](https://img.shields.io/badge/platform-Kali%20Linux%20%7C%20Linux-orange)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/project-active-brightgreen)

**Beacon** is a Python-based vulnerability scanner that detects **OWASP Top 10** vulnerabilities — especially **A05: Security Misconfiguration** and **A04: Insecure Design** — in web applications.

This CLI-based tool is designed for penetration testers, cybersecurity students, CTF participants, and ethical hackers. Built for **Kali Linux**, it requires no GUI and is fully open-source.

---

## 🚀 Features

- ✅ Detects missing HTTP security headers
- ✅ Scans unsafe HTTP methods (PUT, DELETE, etc.)
- ✅ Checks open directories (`/uploads/`, `/images/`)
- ✅ Detects open admin panels (`/admin`, `/phpmyadmin`)
- ✅ Identifies CORS misconfigurations
- ✅ Catches verbose error messages & tech stack leaks
- ✅ Interactive CLI interface (OWASP-based)
- ✅ Works on Kali & other Linux distributions

---

## 📥 Installation

### Requirements

- Python 3.8+
- Kali Linux or any Debian-based OS
- Internet connection (for scanning remote URLs)

### File Structure

beacon-/
├── beacon.py             # ✅ Main scanner script (run this file)
├── requirements.txt      # 📦 Lists Python packages used (currently: requests)
├── LICENSE               # 📜 MIT License file
├── README.md             # 📘 Documentation file (this file)
└── screenshots/          # 🖼️ (Optional) Folder for demo images/screenshots

### Install Python dependencies:

```bash
pip install -r requirements.txt

### File Structure

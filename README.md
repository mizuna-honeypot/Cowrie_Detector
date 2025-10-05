# Cowrie Detector 🕵️‍♂️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/downloads/)

A simple yet powerful Python script for detecting Cowrie SSH honeypots.

---
## Overview

`cowrie_detector.py` is a tool that analyzes and identifies whether a given SSH server is the popular honeypot "Cowrie," based on multiple indicators. It's designed to help honeypot researchers and penetration testers during initial reconnaissance to distinguish between a real system and a cleverly disguised trap.

---
## Key Features

* **Multi-layered Analysis**: Makes a comprehensive judgment by combining SSH banner, credentials, system behavior, and environment information.
* **Lightweight & Portable**: Runs with only Python 3 and the `paramiko` library, requiring no complex setup.
* **Confidence Scoring**: Displays the probability of the target being a Cowrie honeypot as a percentage based on the detected indicators.

---
## How It Works

This tool identifies Cowrie through a four-stage analysis:

1.  **Banner Analysis**: It fetches the target server's SSH banner and compares it against known version strings commonly used by Cowrie.
2.  **Authentication Probing**: It attempts to log in using common default credentials like `root:root` and the Cowrie-specific `phil:phil`.
3.  **Behavioral Analysis**: After a successful login, it executes basic commands like `whoami`. It detects unnatural behaviors, such as the immediate channel closure that Cowrie sometimes exhibits.
4.  **Environment Fingerprinting**: It runs commands like `uname -a` and `cat /etc/passwd` to check if the returned kernel version and user list match Cowrie's default environment.

---
## Prerequisites

* Python 3.x
* `paramiko` library

---
## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/mizuna-honeypot/cowrie_detector.git
    cd cowrie_detector
    ```

2.  **Install the required library:**
    ```bash
    pip install paramiko
    ```
---
## Usage

Run the script from your terminal as follows:

```bash
python3 cowrie_detector.py <TARGET_IP_ADDRESS> [PORT]

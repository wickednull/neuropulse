![image](https://github.com/user-attachments/assets/54b2a3b3-74cd-4b09-b870-26228831af60)

# neuropulse
NeuroPulse is a graphical Python framework for red team operations. It centralizes command-line tools for Wi-Fi attacks (Aircrack-ng), exploitation (Nmap, Metasploit), and IoT analysis. Core features include a process manager to control tasks, a configuration file for customization, and an HTML report generator.

# 🧠 NeuroPulse v2.0
### A Cyber Red Team Fusion Framework

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-2.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)

---

NeuroPulse is a graphical framework built in Python and Tkinter, designed to centralize and streamline the workflows of red team operations and penetration testing. It acts as a unified control panel for a variety of common command-line security tools, allowing an operator to launch scans, execute attacks, manage processes, and log all activity from a single, intuitive interface.

<p align="center">
  </p>

## ⚠️ Disclaimer
This tool is intended for **educational and authorized security testing purposes ONLY**. Using these tools against networks or systems without explicit prior consent is illegal. The developer assumes no liability and is not responsible for any misuse or damage caused by this program. **Always act ethically and within the law.**

## ✨ Key Features

* **Unified GUI:** A clean, tab-based Tkinter interface for managing disparate tools.
* **Cross-Platform Launcher:** Intelligently launches tools in a new terminal on Linux, macOS, and Windows.
* **Process Manager:** Track and kill any background process launched by NeuroPulse from a dedicated tab.
* **External Configuration:** Easily customize default settings (interfaces, tool options) via a `neuropulse_config.json` file.
* **Session Logging & Reporting:** All actions are logged to the screen and a session file, which can be exported as an HTML report.

### Tool Integration
* **📶 Wi-Fi Attacks:**
    * Network discovery (`airodump-ng`)
    * Deauthentication attacks (`aireplay-ng`)
    * Beacon Floods (`mdk4`)
    * WPS Attacks (`reaver`)
    * WPA/WPA2 cracking (`aircrack-ng`)
    * Guided Evil Twin setup (`airbase-ng`)
* **📡 BLE & Zigbee:**
    * Bluetooth LE reconnaissance (`bettercap`)
    * Zigbee PCAP analysis (`tshark`)
* **💥 Exploitation & Network Analysis:**
    * Automated CVE suggestion (`nmap` + `searchsploit`)
    * Metasploit RC file generation and launch (`msfconsole`)
    * Captured hash classification viewer
* **🛠️ Utilities:**
    * Simple binary fuzzer ("BitFlip Engine") with undo capabilities.
    * HTML report generation.

## ⚙️ Prerequisites

NeuroPulse is a wrapper and requires several external command-line tools to be installed and available in your system's PATH.

**Essential Tools:**
* Python 3.8+
* `nmap`
* `aircrack-ng` suite (`airodump-ng`, `aireplay-ng`, `aircrack-ng`, `airbase-ng`)
* `tshark` (from the Wireshark suite)
* `msfconsole` (Metasploit Framework)
* `searchsploit` (Exploit-DB)
* `bettercap`
* `mdk4`
* `reaver`
* `hcxdumptool` (Optional, for PMKID attacks)

For Debian-based systems (like Kali Linux), you can install most of these using:
```bash
sudo apt update && sudo apt install nmap aircrack-ng wireshark metasploit-framework exploitdb bettercap mdk4 reaver -y

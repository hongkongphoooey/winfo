# winfo - Windows System Diagnostics Script

This PowerShell script provides a rapid snapshot of a Windows machine's health and configuration. It generates a two-part report: a System Summary for general info, and Admin Diagnostics (if run with Administrator privileges) for deep-dive troubleshooting.

![winfo in use on Windows 11](https://raw.githubusercontent.com/hongkongphoooey/winfo/refs/heads/master/screenshot.png)

## Key Features
* Identity & Health: OS version, uptime, pending reboots, and live CPU/Memory usage.
* Network Status: IPv4/IPv6, Gateway, Public IP, DNS, and connectivity tests.
* Hardware & Storage: Drive space, disk health, displays, and connected peripherals.
* Security Posture: Windows Defender status, Firewall profiles, TPM, Secure Boot, and BitLocker encryption.
* Advanced Diagnostics: Stopped services, pending updates, critical system events, listening ports, and ARP tables.

## Prerequisites
* Powershell 5.1
* Windows 10 (1607 or later) or Windows 11

## Usage
The program can be run in one of two ways: locally or over the internet.

### Local usage
Download [winfo.ps1](https://raw.githubusercontent.com/hongkongphoooey/winfo/refs/heads/master/winfo.ps1) and run in an interactive PowerShell window - preferably run as Administrator.
You may need to run `Set-ExecutionPolicy Bypass` first.

### From the web
Open PowerShell with desired privilege level and run 

`irm https://spoo.me/winfo | iex`

or 

`irm https://raw.githubusercontent.com/hongkongphoooey/winfo/refs/heads/master/winfo.ps1 | iex`

## License
MIT

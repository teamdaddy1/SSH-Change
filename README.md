# 🔐 SSH & UFW Port Manager Tool
A powerful, interactive command-line tool that helps you:

- Change your SSH port safely  
- Remove/Block SSH ports  
- Allow multiple ports at once (TCP / UDP / Both)  
- Block multiple ports at once (TCP / UDP / Both)  
- Support for ranges like `1000-2000`  
- Support for comma + space separated ports  
- Correct IPv4/IPv6 detection  
- Auto-backup of sshd_config  
- UFW rule reset with backup  
- Clean, menu-based interface  

This script is ideal for VPS owners, hosting providers, panel owners, and anyone who wants safer, easier firewall & SSH management.

---

## 🚀 Features

### 🔑 SSH Management
- Change SSH port (with auto UFW handling)
- Remove SSH port safely
- Auto-backup for `/etc/ssh/sshd_config`
- Automatic SSH restart with fallback

### 🔥 Firewall Management (UFW)
- Allow multiple ports at once
- Block multiple ports at once
- Support:
  - Single ports → `22`
  - Multiple ports → `80,443,25565`
  - Space-separated → `80 443 25565`
  - Ranges → `1000-1500`
  - Mixed → `80,443 1000-1010`
- Allow:
  - TCP only
  - UDP only
  - TCP + UDP
- Block (deny + remove existing rules):
  - TCP only
  - UDP only
  - TCP + UDP

### 🌐 Correct IP Detection
- IPv4 via `ipv4.icanhazip.com`
- IPv6 via `ipv6.icanhazip.com`
- No false IPv6 → IPv4 fallback

### 🛡 Safety
- Auto backup of UFW rules during reset
- Auto sshd restart
- No accidental lockout warnings
- UFW operations handled safely & silently

---

## 📥 Installation & Run

Run directly with:

```bash
bash <(curl -s https://raw.githubusercontent.com/teamdaddy1/SSH-Change/main/ssh-port.sh)

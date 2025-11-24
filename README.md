# 🔐 SSH Port Manager
This is a bash script that allows you to **change**, **remove**, or **block** SSH ports on your VPS.  
The script provides two main features:

1. **Change SSH Port**  
2. **Remove + Block an SSH Port Completely**

It also automatically detects your VPS username and public IP address.

---

## ⚙️ Features

### ✔ Change SSH Port
- Prompts for the new SSH port  
- Validates the port number  
- Updates `/etc/ssh/sshd_config`  
- Resets UFW firewall rules  
- Enables UFW  
- Allows the new SSH port  
- Restarts SSH  
- Shows new SSH command with IP + username  

### ✔ Remove SSH Port Completely
- Removes the specified port from SSH config  
- Blocks the port using UFW  
- Deletes any UFW allow rules for that port  
- Resets port back to default (`#Port 22`)  
- Restarts SSH safely  
- Shows confirmation  

---

## 📥 Run the Script

To run the script directly:

```bash
bash <(curl -s https://raw.githubusercontent.com/teamdaddy1/SSH-Change/main/ssh-port.sh)

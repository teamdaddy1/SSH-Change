# 🔐 SSH Port Changer
This is a bash script that allows you to **safely change your SSH port**.  
It automatically updates your SSH configuration, resets UFW firewall rules, enables UFW, allows the new SSH port, and restarts the SSH service.

You can change your SSH port anytime simply by running the command below.

---

## ⚙️ What This Script Does

- Prompts you for the new SSH port  
- Validates the port number  
- Updates `/etc/ssh/sshd_config`  
- Resets all UFW firewall rules  
- Enables UFW  
- Allows the new SSH port  
- Restarts the SSH service  
- Displays your username and how to access the server with the new port  

---

## 📥 Running the Script

Run the command below:

```bash
bash <(curl -s https://raw.githubusercontent.com/teamdaddy1/SSH-Change/main/ssh-port.sh)

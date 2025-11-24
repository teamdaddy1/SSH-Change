#!/bin/bash

echo "-------------------------------"
echo "     SSH Port Changer Tool"
echo "-------------------------------"

# Get VPS username
USERNAME=$(whoami)

# Ask for new SSH port
read -rp "Enter the new SSH port you want to set: " SSH_PORT

# Validate port number
if [[ $SSH_PORT -lt 1 || $SSH_PORT -gt 65535 ]]; then
    echo "❌ Invalid port number! Must be between 1–65535."
    exit 1
fi

echo ""
echo "➡ Updating SSH port to: $SSH_PORT"
echo ""

# Update sshd_config
sed -i "s/^#Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config

echo "➡ Resetting UFW firewall rules..."
ufw --force reset

echo "➡ Enabling UFW..."
ufw --force enable

echo "➡ Allowing new SSH port: $SSH_PORT"
ufw allow "$SSH_PORT"/tcp > /dev/null

echo "➡ Restarting SSH service..."
systemctl restart sshd

echo ""
echo "✅ SSH port has been successfully changed!"
echo "-----------------------------------------------"
echo " ➤ Username : $USERNAME"
echo " ➤ New SSH Port : $SSH_PORT"
echo "-----------------------------------------------"
echo "Now access your VPS with:"
echo ""
echo "ssh $USERNAME@YOUR_SERVER_IP -p $SSH_PORT"
echo ""
echo "⚠️ Don't close this session until you confirm SSH login works!"

#!/bin/bash

echo "--------------------------------------"
echo "        SSH Port Manager Tool"
echo "--------------------------------------"

# Fetch VPS username
USERNAME=$(whoami)

# Fetch Public IP
SERVER_IP=$(curl -s ifconfig.me)

# Menu
echo "Select an option:"
echo "1) Change SSH Port"
echo "2) Remove SSH Port (Block & Disable)"
read -rp "Enter choice (1/2): " CHOICE

# ------------------------------
#  OPTION 1 → CHANGE SSH PORT
# ------------------------------
if [[ "$CHOICE" == "1" ]]; then

    read -rp "Enter the new SSH port you want to set: " SSH_PORT

    # Validate port
    if [[ $SSH_PORT -lt 1 || $SSH_PORT -gt 65535 ]]; then
        echo "❌ Invalid port number! Must be between 1–65535."
        exit 1
    fi

    echo ""
    echo "➡ Updating SSH port to: $SSH_PORT"

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
    echo "----------------------------------------------"
    echo " ➤ Username : $USERNAME"
    echo " ➤ Server IP : $SERVER_IP"
    echo " ➤ New SSH Port : $SSH_PORT"
    echo "----------------------------------------------"
    echo "Connect using:"
    echo "ssh $USERNAME@$SERVER_IP -p $SSH_PORT"
    echo ""
    echo "⚠️ Do NOT close this session until you confirm the new SSH port works!"
    exit 0
fi


# ------------------------------------
#  OPTION 2 → REMOVE SSH PORT COMPLETELY
# ------------------------------------
if [[ "$CHOICE" == "2" ]]; then

    read -rp "Enter the SSH port you want to remove & block: " DEL_PORT

    # Validate port
    if [[ $DEL_PORT -lt 1 || $DEL_PORT -gt 65535 ]]; then
        echo "❌ Invalid port number! Must be between 1–65535."
        exit 1
    fi

    echo ""
    echo "➡ Removing SSH port $DEL_PORT from sshd_config..."

    # Remove all Port entries and reset to default (22)
    sed -i "/^Port $DEL_PORT/d" /etc/ssh/sshd_config
    sed -i "s/^Port .*/#Port 22/" /etc/ssh/sshd_config

    echo "➡ Reloading UFW rules..."
    ufw deny "$DEL_PORT"/tcp > /dev/null
    ufw delete allow "$DEL_PORT"/tcp > /dev/null 2>&1

    echo "➡ Restarting SSH service..."
    systemctl restart sshd

    echo ""
    echo "🛑 SSH port $DEL_PORT has been removed & blocked!"
    echo "----------------------------------------------"
    echo " ➤ Username : $USERNAME"
    echo " ➤ Server IP : $SERVER_IP"
    echo " ➤ Removed SSH Port : $DEL_PORT"
    echo "----------------------------------------------"
    echo "SSH now works only on the remaining allowed ports."
    echo "If you removed your active SSH port, use VNC/console."
    exit 0
fi

echo "❌ Invalid option. Please run the script again."

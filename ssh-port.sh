#!/bin/bash
set -euo pipefail

# SSH + UFW Port Manager (multiple ports, ranges, tcp/udp/both)
# Supports input like: 80,443 1000-1010 25565

BACKUP_DIR="/root/sshport_backups"
mkdir -p "$BACKUP_DIR"

echo "--------------------------------------"
echo "        SSH & UFW Port Manager"
echo "--------------------------------------"

# Helpers
info()    { printf " \e[1;34m→\e[0m %s\n" "$*"; }
success() { printf " \e[1;32m✔\e[0m %s\n" "$*"; }
warn()    { printf " \e[1;33m⚠\e[0m %s\n" "$*"; }
error()   { printf " \e[1;31m✖\e[0m %s\n" "$*"; }

# Fetch details
USERNAME=$(whoami)
SERVER_IPV4=$(curl -s https://ipv4.icanhazip.com || echo "No IPv4 detected")
SERVER_IPV6=$(curl -s https://ipv6.icanhazip.com || echo "No IPv6 detected")

# Validate a single port number
is_valid_port() {
    local p=$1
    [[ $p =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

# Expand input into an array of ports (handles commas, spaces, ranges)
# Usage: parse_ports "80,443 1000-1005"
parse_ports() {
    local input="$*"
    local token
    local -a out=()
    # Replace commas with spaces, normalize
    input="${input//,/ }"
    for token in $input; do
        if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start=${BASH_REMATCH[1]}
            local end=${BASH_REMATCH[2]}
            if (( start > end )); then
                # swap
                local tmp=$start; start=$end; end=$tmp
            fi
            for ((p=start; p<=end; p++)); do
                out+=("$p")
            done
        elif is_valid_port "$token"; then
            out+=("$token")
        else
            warn "Skipping invalid token: $token"
        fi
    done

    # Deduplicate and print as newline-separated
    # Use associative array to dedup (bash 4+)
    declare -A seen=()
    for p in "${out[@]}"; do
        seen["$p"]=1
    done
    for p in "${!seen[@]}"; do
        echo "$p"
    done
}

# Add UFW rule safely
ufw_allow() {
    local port=$1
    local proto=${2:-tcp}
    info "Allowing $port/$proto"
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${port}/${proto} returned non-zero"
}

# Block & remove allow (deny + remove allow if exists)
ufw_block() {
    local port=$1
    local proto=${2:-tcp}
    info "Blocking $port/$proto (deny + remove allow if exists)"
    ufw deny "${port}/${proto}" >/dev/null 2>&1 || warn "ufw deny ${port}/${proto} returned non-zero"
    # Try to delete allow rule (non-interactive)
    # If a rule exists, delete it. Use grep to check presence first.
    if ufw status numbered | grep -q "${port}/${proto}"; then
        # ufw delete requires confirmation; pipe 'y' to it
        echo "y" | ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
}

# Backup sshd_config
backup_sshd_config() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local dst="$BACKUP_DIR/sshd_config.$ts"
    cp -a /etc/ssh/sshd_config "$dst"
    success "Backed up /etc/ssh/sshd_config → $dst"
}

# Update sshd_config port (replace all Port lines with the chosen port)
set_ssh_port() {
    local port=$1
    backup_sshd_config
    # If there are multiple Port entries, remove all and append a single "Port <port>"
    # Keep commented default line
    sed -i '/^Port[[:space:]]\+[0-9]\+/d' /etc/ssh/sshd_config
    # Ensure there's a commented default line (#Port 22)
    if ! grep -q '^#Port 22' /etc/ssh/sshd_config; then
        sed -i '1i#Port 22' /etc/ssh/sshd_config
    fi
    # Append new Port line (if not present)
    if ! grep -q "^Port $port" /etc/ssh/sshd_config; then
        echo "Port $port" >> /etc/ssh/sshd_config
    fi
    success "sshd_config updated to Port $port"
}

# Remove specific port entries from sshd_config
remove_ssh_port_entry() {
    local port=$1
    backup_sshd_config
    sed -i "/^Port[[:space:]]\+$port/d" /etc/ssh/sshd_config
    # if after deletion there's no Port line, leave commented default
    if ! grep -q '^Port[[:space:]]\+[0-9]\+' /etc/ssh/sshd_config; then
        if ! grep -q '^#Port 22' /etc/ssh/sshd_config; then
            sed -i '1i#Port 22' /etc/ssh/sshd_config
        fi
    fi
    success "Removed Port $port from sshd_config (if it existed)"
}

# Restart sshd safely (no automatic rollback here; user must ensure they have console access)
restart_sshd() {
    info "Restarting ssh service..."
    if systemctl restart sshd 2>/dev/null; then
        success "sshd restarted"
    else
        warn "Failed to restart sshd via systemctl; trying /etc/init.d/ssh restart"
        if /etc/init.d/ssh restart 2>/dev/null; then
            success "sshd restarted via init.d"
        else
            error "Could not restart sshd. Check service status!"
        fi
    fi
}

# Reset UFW (with backup) - used only when requested (we won't reset by default for allow/deny ops)
ufw_reset_with_backup() {
    info "Backing up UFW rules..."
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    cp -a /etc/ufw/user.rules "/etc/ufw/user.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/before.rules "/etc/ufw/before.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/after.rules "/etc/ufw/after.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/user6.rules "/etc/ufw/user6.rules.$ts" 2>/dev/null || true
    info "Resetting UFW (this will remove all current rules)..."
    ufw --force reset >/dev/null 2>&1 || warn "ufw reset returned non-zero"
    ufw --force enable >/dev/null 2>&1 || warn "ufw enable returned non-zero"
    success "UFW reset and enabled"
}

# Print menu
print_menu() {
    cat <<'MENU'
Select an option:
 1) Change SSH Port (single)
 2) Remove SSH Port (single)
 3) Allow ports (TCP)        -> accept multiple/ranges
 4) Allow ports (UDP)        -> accept multiple/ranges
 5) Allow ports (TCP+UDP)    -> accept multiple/ranges
 6) Block ports (TCP)        -> deny + remove allow
 7) Block ports (UDP)
 8) Block ports (TCP+UDP)
 9) Reset UFW (backup & reset rules)
 0) Exit
MENU
}

# MAIN
print_menu
read -rp "Enter choice: " CHOICE

case "$CHOICE" in
    1)
        read -rp "Enter the new SSH port (single): " SSH_PORT
        if ! is_valid_port "$SSH_PORT"; then error "Invalid port"; exit 1; fi
        set_ssh_port "$SSH_PORT"
        # Optional: reset firewall to a clean state (ask user)
        read -rp "Do you want to reset UFW rules (recommended to avoid conflicts)? [y/N]: " yn
        if [[ "${yn,,}" == "y" ]]; then
            ufw_reset_with_backup
        else
            info "Skipping UFW reset"
            ufw --force enable >/dev/null 2>&1 || true
        fi
        ufw_allow "$SSH_PORT" tcp
        restart_sshd
        success "SSH port changed to $SSH_PORT"
        echo ""
        echo " ➤ Username : $USERNAME"
        echo " ➤ IPv4     : $SERVER_IPV4"
        echo " ➤ IPv6     : $SERVER_IPV6"
        echo " ➤ New SSH Port : $SSH_PORT"
        echo ""
        echo "Connect (IPv4): ssh ${USERNAME}@${SERVER_IPV4} -p ${SSH_PORT}"
        if [[ "$SERVER_IPV6" != "No IPv6 detected" ]]; then
            echo "Connect (IPv6): ssh ${USERNAME}@[${SERVER_IPV6}] -p ${SSH_PORT}"
        fi
        ;;

    2)
        read -rp "Enter the SSH port to remove & block (single): " DEL_PORT
        if ! is_valid_port "$DEL_PORT"; then error "Invalid port"; exit 1; fi
        remove_ssh_port_entry "$DEL_PORT"
        ufw_block "$DEL_PORT" tcp
        restart_sshd
        success "Removed & blocked SSH port: $DEL_PORT"
        echo " ➤ IPv4 : $SERVER_IPV4"
        echo " ➤ IPv6 : $SERVER_IPV6"
        ;;

    3|4|5|6|7|8)
        read -rp "Enter ports (commas/spaces/ranges allowed, e.g. 80,443 1000-1005): " PORT_INPUT
        # Parse ports into lines
        mapfile -t PORTS < <(parse_ports "$PORT_INPUT")
        if [[ ${#PORTS[@]} -eq 0 ]]; then error "No valid ports parsed"; exit 1; fi

        # Determine protocol & action
        case "$CHOICE" in
            3) proto_list=("tcp"); action="allow" ;;
            4) proto_list=("udp"); action="allow" ;;
            5) proto_list=("tcp" "udp"); action="allow" ;;
            6) proto_list=("tcp"); action="block" ;;
            7) proto_list=("udp"); action="block" ;;
            8) proto_list=("tcp" "udp"); action="block" ;;
        esac

        info "Parsed ports: ${PORTS[*]}"
        for p in "${PORTS[@]}"; do
            for proto in "${proto_list[@]}"; do
                if [[ "$action" == "allow" ]]; then
                    ufw_allow "$p" "$proto"
                else
                    ufw_block "$p" "$proto"
                fi
            done
        done

        success "Operation complete for ports: ${PORTS[*]}"
        ;;

    9)
        read -rp "This will backup and RESET UFW (remove all rules). Continue? [y/N]: " yn
        if [[ "${yn,,}" == "y" ]]; then
            ufw_reset_with_backup
        else
            info "Cancelled UFW reset"
        fi
        ;;

    0)
        info "Bye."
        exit 0
        ;;

    *)
        error "Invalid choice"
        exit 1
        ;;
esac

exit 0

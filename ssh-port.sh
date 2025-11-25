#!/bin/bash
set -euo pipefail

# ============================================
#     SSH + UFW PORT MANAGER (ENHANCED)
#     - color menu
#     - logging
#     - rollback safety
#     - auto SSH test
#     - UFW multi-port (ranges)
#     - Auto-Fix sshd_config validator & fixer (Option 10)
# ============================================

BACKUP_DIR="/root/sshport_backups"
LOG_FILE="/var/log/sshport_manager.log"
mkdir -p "$BACKUP_DIR"
touch "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Colors
BLUE="\e[1;34m"
GREEN="\e[1;32m"
YELLOW="\e[1;33m"
RED="\e[1;31m"
RESET="\e[0m"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" >> "$LOG_FILE"
}

color() { printf " $1$2${RESET}\n"; }

info()    { color "$BLUE"   "→ $*"; log "INFO: $*"; }
success() { color "$GREEN"  "✔ $*"; log "SUCCESS: $*"; }
warn()    { color "$YELLOW" "⚠ $*"; log "WARN: $*"; }
error()   { color "$RED"    "✖ $*"; log "ERROR: $*"; }

USERNAME=$(whoami)
SERVER_IPV4=$(curl -s https://ipv4.icanhazip.com || echo "No IPv4")
SERVER_IPV6=$(curl -s https://ipv6.icanhazip.com || echo "No IPv6")

is_valid_port() {
    local p=$1
    [[ $p =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

# Expand ports: "80,443 1000-2000"
parse_ports() {
    local input="$*"
    local token
    local -a out=()
    input="${input//,/ }"
    for token in $input; do
        if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start=${BASH_REMATCH[1]}
            local end=${BASH_REMATCH[2]}
            ((start > end)) && { local tmp=$start; start=$end; end=$tmp; }
            for ((p=start;p<=end;p++)); do out+=("$p"); done
        elif is_valid_port "$token"; then
            out+=("$token")
        else warn "Skipping invalid port token: $token"; fi
    done
    declare -A dedup=()
    for p in "${out[@]}"; do dedup["$p"]=1; done
    for p in "${!dedup[@]}"; do echo "$p"; done
}

# UFW helpers
ufw_allow() {
    local port=$1 proto=${2:-tcp}
    info "Allowing $port/$proto"
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${port}/${proto} returned non-zero"
    log "UFW allow $port/$proto"
}

ufw_block() {
    local port=$1 proto=${2:-tcp}
    info "Blocking $port/$proto (deny + remove allow if exists)"
    ufw deny "${port}/${proto}" >/dev/null 2>&1 || true
    # remove allow rule if exists
    if ufw status numbered | grep -q "${port}/${proto}"; then
        echo y | ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
    fi
    log "UFW block $port/$proto"
}

backup_sshd_config() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local dst="$BACKUP_DIR/sshd_config.$ts"
    cp -a /etc/ssh/sshd_config "$dst"
    success "Backup saved → $dst"
    echo "$dst"
}

# Restart sshd with fallback
restart_sshd() {
    info "Restarting SSH..."
    if systemctl restart sshd 2>/dev/null; then
        success "SSHD restarted (systemctl)"
    else
        warn "systemctl restart failed; trying service restart"
        if service ssh restart 2>/dev/null; then
            success "SSHD restarted (service)"
        else
            error "SSH restart FAILED. Manual intervention required!"
        fi
    fi
}

# SSH connectivity test (local loopback check)
# Returns 0 if something listening on port
ssh_port_local_test() {
    local port=$1
    timeout 5 bash -c "cat < /dev/null > /dev/tcp/127.0.0.1/$port" 2>/dev/null
}

# Full safe SSH port setter with rollback & test
set_ssh_port() {
    local port=$1
    local backup_file
    backup_file=$(backup_sshd_config)

    info "Removing any existing Port lines (commented or not)"
    # remove any line that contains Port <number> with any leading spaces and optional #
    sed -i '/^[[:space:]]*#\{0,1\}[[:space:]]*Port[[:space:]]\+[0-9]\+/d' /etc/ssh/sshd_config

    info "Appending clean Port $port"
    echo "Port $port" >> /etc/ssh/sshd_config

    info "Validating sshd_config syntax..."
    if sshd -t 2>/dev/null; then
        success "sshd_config syntax OK"
    else
        error "sshd_config syntax error! Restoring backup"
        cp "$backup_file" /etc/ssh/sshd_config
        restart_sshd
        exit 1
    fi

    info "Restarting SSH to apply port change (but we will test before finalizing)..."
    restart_sshd

    info "Testing SSH on localhost port $port..."
    if ssh_port_local_test "$port"; then
        success "Local test succeeded: sshd listening on $port"
        log "Port $port active"
    else
        error "Local test failed. Restoring backup sshd_config and rebooting SSH."
        cp "$backup_file" /etc/ssh/sshd_config
        restart_sshd
        exit 1
    fi
}

# Remove a specific Port entry and leave commented default if none left
remove_ssh_port_entry() {
    local port=$1
    local backup_file
    backup_file=$(backup_sshd_config)

    sed -i "/^[[:space:]]*#\{0,1\}[[:space:]]*Port[[:space:]]\+$port/d" /etc/ssh/sshd_config

    # if no Port left, add commented default
    if ! grep -q '^Port[[:space:]]\+[0-9]\+' /etc/ssh/sshd_config; then
        echo "#Port 22" >> /etc/ssh/sshd_config
    fi

    info "Validating sshd_config syntax after removal..."
    if sshd -t 2>/dev/null; then
        success "sshd_config syntax OK after removal"
    else
        error "sshd_config invalid after removal - restoring backup"
        cp "$backup_file" /etc/ssh/sshd_config
        restart_sshd
        exit 1
    fi
    success "Removed Port $port"
}

# Auto-Fix sshd_config validator & fixer
auto_fix_sshd_config() {
    info "Starting sshd_config validator & auto-fix"

    local backup_file
    backup_file=$(backup_sshd_config)

    local tmpfile
    tmpfile=$(mktemp)
    cp /etc/ssh/sshd_config "$tmpfile"

    # Normalize: remove duplicate Port lines, trim whitespace, ensure single Port line commented or real
    # 1) Remove duplicate Port lines (any format)
    sed -i '/^[[:space:]]*#\{0,1\}[[:space:]]*Port[[:space:]]\+[0-9]\+/d' "$tmpfile"
    # 2) Add commented default line if none
    if ! grep -q '^#Port 22' "$tmpfile"; then
        sed -i '1i#Port 22' "$tmpfile"
    fi

    # 3) Ensure permissions are correct
    chmod 600 "$tmpfile"

    # 4) Enforce safe options: PermitRootLogin no, PasswordAuthentication no, PermitEmptyPasswords no
    # Replace or add each directive
    if grep -q '^PermitRootLogin' "$tmpfile"; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$tmpfile"
    else
        echo "PermitRootLogin no" >> "$tmpfile"
    fi

    if grep -q '^PasswordAuthentication' "$tmpfile"; then
        sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' "$tmpfile"
    else
        echo "PasswordAuthentication no" >> "$tmpfile"
    fi

    if grep -q '^PermitEmptyPasswords' "$tmpfile"; then
        sed -i 's/^PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$tmpfile"
    else
        echo "PermitEmptyPasswords no" >> "$tmpfile"
    fi

    # 5) Ensure HostKey directives exist for common names; if missing, warn (do NOT auto-generate keys here)
    for keyfile in /etc/ssh/ssh_host_rsa_key /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_ed25519_key; do
        if [ -f "$keyfile" ]; then
            # Ensure there's a HostKey line referencing it
            if ! grep -q "$(basename "$keyfile")" "$tmpfile"; then
                echo "HostKey $keyfile" >> "$tmpfile"
            fi
        else
            warn "Host key not found: $keyfile"
        fi
    done

    # 6) Write tmpfile back to /etc/ssh/sshd_config and test
    cp "$tmpfile" /etc/ssh/sshd_config
    rm -f "$tmpfile"

    info "Testing new sshd_config with sshd -t..."
    if sshd -t 2>/tmp/sshd_test_err; then
        success "sshd -t OK. Restarting SSH..."
        restart_sshd
        success "Auto-fix applied successfully"
        log "Auto-fix succeeded"
    else
        warn "sshd -t reported errors:"
        sed -n '1,200p' /tmp/sshd_test_err
        error "Auto-fix failed. Restoring backup."
        cp "$backup_file" /etc/ssh/sshd_config
        restart_sshd
        log "Auto-fix failed; backup restored"
        rm -f /tmp/sshd_test_err
        return 1
    fi

    rm -f /tmp/sshd_test_err 2>/dev/null || true
    return 0
}

# UFW reset with backup
ufw_reset_with_backup() {
    info "Backing up UFW rules..."
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    cp -a /etc/ufw "/etc/ufw_backup_$ts" 2>/dev/null || true
    ufw --force reset >/dev/null 2>&1 || warn "ufw reset non-zero"
    ufw --force enable >/dev/null 2>&1 || warn "ufw enable non-zero"
    success "UFW reset complete"
}

# Menu
print_menu() {
    echo -e "${GREEN}"
    cat <<'MENU'
─────────────────────────────────────────────
            SSH & UFW PORT MANAGER
─────────────────────────────────────────────
 1) Change SSH Port (Safe + Rollback)
 2) Remove SSH Port
 3) Allow ports (TCP)
 4) Allow ports (UDP)
 5) Allow ports (TCP+UDP)
 6) Block ports (TCP)
 7) Block ports (UDP)
 8) Block ports (TCP+UDP)
 9) Reset UFW
10) Auto-Fix SSH Configuration (validator & fixer)
 0) Exit
─────────────────────────────────────────────
MENU
    echo -e "${RESET}"
}

print_menu
read -rp "Enter choice: " CHOICE

case $CHOICE in
    1)
        read -rp "Enter new SSH port: " SSH_PORT
        is_valid_port "$SSH_PORT" || { error "Invalid port"; exit 1; }
        set_ssh_port "$SSH_PORT"
        read -rp "Open this port in UFW? [Y/n]: " ynp
        if [[ "${ynp,,}" != "n" ]]; then ufw_allow "$SSH_PORT" tcp; fi
        success "SSH port changed → $SSH_PORT"
        echo "IPv4: $SERVER_IPV4"
        echo "IPv6: $SERVER_IPV6"
        ;;

    2)
        read -rp "Enter SSH port to remove: " DEL_PORT
        is_valid_port "$DEL_PORT" || { error "Invalid port"; exit 1; }
        remove_ssh_port_entry "$DEL_PORT"
        ufw_block "$DEL_PORT" tcp
        success "Removed & blocked SSH port → $DEL_PORT"
        ;;

    3|4|5|6|7|8)
        read -rp "Enter ports (comma/space/range e.g. 80,443 1000-2000): " PORT_INPUT
        mapfile -t PORTS < <(parse_ports "$PORT_INPUT")
        if [[ ${#PORTS[@]} -eq 0 ]]; then error "No valid ports parsed"; exit 1; fi

        case "$CHOICE" in
            3) PROT=("tcp"); ACTION="allow" ;;
            4) PROT=("udp"); ACTION="allow" ;;
            5) PROT=("tcp" "udp"); ACTION="allow" ;;
            6) PROT=("tcp"); ACTION="block" ;;
            7) PROT=("udp"); ACTION="block" ;;
            8) PROT=("tcp" "udp"); ACTION="block" ;;
        esac

        for p in "${PORTS[@]}"; do
            for proto in "${PROT[@]}"; do
                if [[ "$ACTION" == "allow" ]]; then ufw_allow "$p" "$proto"; else ufw_block "$p" "$proto"; fi
            done
        done
        success "Operation completed for ports: ${PORTS[*]}"
        ;;

    9)
        read -rp "This will backup and RESET UFW (remove all rules). Continue? [y/N]: " yn
        [[ "${yn,,}" == "y" ]] && ufw_reset_with_backup || info "Cancelled UFW reset"
        ;;

    10)
        warn "Auto-Fix will attempt to modify /etc/ssh/sshd_config and restart SSH."
        read -rp "Proceed with Auto-Fix? [y/N]: " yfix
        if [[ "${yfix,,}" == "y" ]]; then
            if auto_fix_sshd_config; then success "Auto-Fix finished successfully"; else error "Auto-Fix failed or restored backup"; fi
        else
            info "Auto-Fix cancelled"
        fi
        ;;

    0) info "Bye."; exit 0 ;;
    *) error "Invalid selection!" ; exit 1 ;;
esac

exit 0

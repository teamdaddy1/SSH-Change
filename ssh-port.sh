#!/bin/bash
set -euo pipefail

# SSH + UFW Port Manager v2
# Features:
#  - Change/remove SSH ports safely
#  - UFW allow/deny for IPv4 & IPv6 (if IPv6 enabled in UFW)
#  - Port conflict detection (ss/netstat)
#  - Auto-rollback on failed sshd restart (uses last backup)
#  - Logging to /var/log/sshport_manager.log
#
# Run as root.

LOGFILE="/var/log/sshport_manager.log"
BACKUP_DIR="/root/sshport_backups"
LAST_BACKUP=""
mkdir -p "$BACKUP_DIR"
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Colors
info()    { printf " \e[1;34m→\e[0m %s\n" "$*"; }
success() { printf " \e[1;32m✔\e[0m %s\n" "$*"; }
warn()    { printf " \e[1;33m⚠\e[0m %s\n" "$*"; }
error()   { printf " \e[1;31m✖\e[0m %s\n" "$*"; }

# Logging helper
log() {
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf "%s %s\n" "$ts" "$*" >> "$LOGFILE"
}

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
parse_ports() {
    local input="$*"
    local token
    local -a out=()
    input="${input//,/ }"
    for token in $input; do
        if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
            local start=${BASH_REMATCH[1]}
            local end=${BASH_REMATCH[2]}
            if (( start > end )); then
                local tmp=$start; start=$end; end=$tmp
            fi
            for ((p=start; p<=end; p++)); do out+=("$p"); done
        elif is_valid_port "$token"; then
            out+=("$token")
        else
            warn "Skipping invalid token: $token"
            log "WARN: Skipping invalid token: $token"
        fi
    done

    # Deduplicate (preserve arbitrary order)
    declare -A seen=()
    for p in "${out[@]}"; do seen["$p"]=1; done
    for p in "${!seen[@]}"; do echo "$p"; done
}

# Check whether UFW has IPv6 enabled in /etc/default/ufw or /etc/ufw/ufw.conf
ufw_ipv6_enabled() {
    # check common place
    if grep -Eqi '^IPV6=yes' /etc/default/ufw 2>/dev/null; then
        return 0
    fi
    if grep -Eqi '^IPV6=yes' /etc/ufw/ufw.conf 2>/dev/null; then
        return 0
    fi
    return 1
}

# Port conflict detection using ss/netstat
# Returns: 0 if free or only sshd is bound; 1 if conflict with another process
check_port_conflict() {
    local port=$1
    # Prefer ss
    if command -v ss >/dev/null 2>&1; then
        # Check both tcp and udp listeners (all)
        # Example ss output lines contain LISTEN and :PORT
        if ss -ltnp 2>/dev/null | grep -qE "[:.]${port}\s"; then
            # capture owner
            local line; line=$(ss -ltnp 2>/dev/null | grep -E "[:.]${port}\s" | head -n1 || true)
            if [[ -n "$line" ]]; then
                # Extract process name from "users:((" pattern or pid=...
                local proc; proc=$(echo "$line" | sed -n 's/.*pid=\([0-9]*\),.*/\1/p' || true)
                if [[ -n "$proc" ]]; then
                    local pname; pname=$(ps -p "$proc" -o comm= 2>/dev/null || true)
                    if [[ "$pname" == "sshd" || "$pname" == "sshd:" ]]; then
                        return 0
                    else
                        warn "Port $port is already used by process: PID=$proc ($pname)"
                        log "CONFLICT: Port $port used by PID=$proc ($pname)"
                        return 1
                    fi
                else
                    # If we can't determine pid/name, assume it's used -- abort
                    warn "Port $port appears in ss output but process unknown; aborting"
                    log "CONFLICT: Port $port appears in ss output but process unknown"
                    return 1
                fi
            fi
        fi
        # Also check UDP listeners
        if ss -lunp 2>/dev/null | grep -qE "[:.]${port}\s"; then
            local line; line=$(ss -lunp 2>/dev/null | grep -E "[:.]${port}\s" | head -n1 || true)
            if [[ -n "$line" ]]; then
                local proc; proc=$(echo "$line" | sed -n 's/.*pid=\([0-9]*\),.*/\1/p' || true)
                if [[ -n "$proc" ]]; then
                    local pname; pname=$(ps -p "$proc" -o comm= 2>/dev/null || true)
                    if [[ "$pname" == "sshd" || "$pname" == "sshd:" ]]; then
                        return 0
                    else
                        warn "Port $port (udp) is already used by process: PID=$proc ($pname)"
                        log "CONFLICT: Port $port (udp) used by PID=$proc ($pname)"
                        return 1
                    fi
                else
                    warn "Port $port (udp) appears in ss output but process unknown; aborting"
                    log "CONFLICT: Port $port (udp) appears in ss output but process unknown"
                    return 1
                fi
            fi
        fi
    fi

    # Fallback to netstat if ss not present
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tulpn 2>/dev/null | grep -qE "[:.]${port}\s"; then
            local line; line=$(netstat -tulpn 2>/dev/null | grep -E "[:.]${port}\s" | head -n1 || true)
            if [[ -n "$line" ]]; then
                local pidinfo; pidinfo=$(echo "$line" | awk '{print $7}')
                if [[ "$pidinfo" == "-" ]]; then
                    warn "Port $port in netstat but PID unknown; aborting"
                    log "CONFLICT: Port $port netstat shows in use but PID unknown"
                    return 1
                fi
                local pid=${pidinfo%%/*}
                local pname; pname=$(ps -p "$pid" -o comm= 2>/dev/null || true)
                if [[ "$pname" == "sshd" || "$pname" == "sshd:" ]]; then
                    return 0
                else
                    warn "Port $port is already used by process: PID=$pid ($pname)"
                    log "CONFLICT: Port $port used by PID=$pid ($pname)"
                    return 1
                fi
            fi
        fi
    fi

    # no conflicts detected
    return 0
}

# Backup sshd_config and record path to LAST_BACKUP
backup_sshd_config() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local src="/etc/ssh/sshd_config"
    local dst="$BACKUP_DIR/sshd_config.$ts"
    if cp -a "$src" "$dst"; then
        LAST_BACKUP="$dst"
        log "Backup created: $dst"
        success "Backed up /etc/ssh/sshd_config → $dst"
    else
        error "Failed to backup $src"
        log "ERROR: Failed to backup $src"
        return 1
    fi
}

# Rollback to LAST_BACKUP (used when restart fails)
rollback_last_sshd_backup() {
    if [[ -z "$LAST_BACKUP" ]] || [[ ! -f "$LAST_BACKUP" ]]; then
        error "No valid backup available to rollback!"
        log "ERROR: No valid backup ($LAST_BACKUP) to rollback"
        return 1
    fi
    cp -a "$LAST_BACKUP" /etc/ssh/sshd_config
    log "Rollback applied from $LAST_BACKUP"
    warn "Rollback: Restored sshd_config from $LAST_BACKUP"
    # Try restart
    if systemctl restart sshd 2>/dev/null; then
        success "sshd restarted after rollback"
        log "SUCCESS: sshd restarted after rollback"
        return 0
    else
        warn "Rollback restart failed; try /etc/init.d/ssh restart"
        if /etc/init.d/ssh restart 2>/dev/null; then
            success "sshd restarted via init.d after rollback"
            log "SUCCESS: sshd restarted via init.d after rollback"
            return 0
        else
            error "CRITICAL: Could not restart sshd after rollback. Manual intervention required!"
            log "CRITICAL: Could not restart sshd after rollback"
            return 2
        fi
    fi
}

# Update sshd_config port (remove all Port lines then add one)
set_ssh_port() {
    local port=$1
    backup_sshd_config

    # Remove ALL existing Port lines (commented or not)
    sed -i '/^[[:space:]]*#*[[:space:]]*Port[[:space:]]\+[0-9]\+/Id' /etc/ssh/sshd_config

    # Append new Port line
    echo "Port $port" >> /etc/ssh/sshd_config
    log "Updated sshd_config: Port $port"
    success "sshd_config updated to Port $port"
}

# Remove specific port entry (only that exact port)
remove_ssh_port_entry() {
    local port=$1
    backup_sshd_config
    sed -i "/^[[:space:]]*#*[[:space:]]*Port[[:space:]]\+$port/Id" /etc/ssh/sshd_config
    # Ensure at least one Port exists: if none, leave default comment (#Port 22)
    if ! grep -qE '^[[:space:]]*#*[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config; then
        # Add commented default to top if missing
        if ! grep -q '^#Port 22' /etc/ssh/sshd_config; then
            sed -i '1i#Port 22' /etc/ssh/sshd_config
        fi
    fi
    success "Removed Port $port from sshd_config (if it existed)"
    log "Removed Port $port from sshd_config (if present)"
}

# Restart sshd safely: if fails -> rollback
restart_sshd() {
    info "Restarting ssh service..."
    log "Attempting to restart sshd"
    if systemctl restart sshd 2>/dev/null; then
        success "sshd restarted"
        log "sshd restarted successfully"
        return 0
    else
        warn "systemctl restart sshd failed; trying init.d"
        log "systemctl restart sshd failed"
        if /etc/init.d/ssh restart 2>/dev/null; then
            success "sshd restarted via init.d"
            log "sshd restarted via init.d successfully"
            return 0
        else
            warn "sshd failed to restart - performing rollback"
            log "sshd failed to restart after changes - starting rollback"
            rollback_last_sshd_backup
            return 1
        fi
    fi
}

# UFW allow / deny wrappers — handle IPv6 awareness
ufw_allow() {
    local port=$1
    local proto=${2:-tcp}
    info "Allowing $port/$proto (UFW)"
    log "UFW allow $port/$proto"
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${port}/${proto} returned non-zero"
    # IPv6 check — ufw will handle IPv6 if enabled. Warn if disabled.
    if ! ufw_ipv6_enabled; then
        warn "UFW IPv6 appears disabled. If you need IPv6 rules, enable IPV6 in /etc/ufw/ufw.conf"
        log "WARN: UFW IPv6 appears disabled"
    fi
}

ufw_block() {
    local port=$1
    local proto=${2:-tcp}
    info "Blocking $port/$proto (UFW deny + remove allow if exists)"
    log "UFW deny $port/$proto"
    ufw deny "${port}/${proto}" >/dev/null 2>&1 || warn "ufw deny ${port}/${proto} returned non-zero"
    # Try to remove specific allow rules if present
    # Non-interactive deletion: find numbered lines and delete
    if ufw status numbered 2>/dev/null | grep -q "${port}/${proto}"; then
        # find matching rule numbers and delete them
        # capture rule numbers (in reverse order for safe deletion)
        local nums
        nums=$(ufw status numbered 2>/dev/null | nl -ba -v0 | sed -n "s/^\s*\[\([0-9]\+\)\]\s*.*${port}\/${proto}.*/\1/p" | sort -rn || true)
        for n in $nums; do
            # Use expect-like piping to handle confirmation
            echo "$n" >/tmp/ufw_del_cmd 2>/dev/null || true
            echo "y" | ufw delete "$n" >/dev/null 2>&1 || true
            # Note: depending on ufw version the above may not delete as expected; keep best effort
        done
    fi
    if ! ufw_ipv6_enabled; then
        warn "UFW IPv6 appears disabled; IPv6 deny not applied"
        log "WARN: UFW IPv6 disabled; deny not applied for IPv6"
    fi
}

# Reset UFW (with backup)
ufw_reset_with_backup() {
    info "Backing up UFW rules..."
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    cp -a /etc/ufw/user.rules "/etc/ufw/user.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/before.rules "/etc/ufw/before.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/after.rules "/etc/ufw/after.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/user6.rules "/etc/ufw/user6.rules.$ts" 2>/dev/null || true
    log "UFW rules backed up with ts=$ts"
    info "Resetting UFW (this will remove all current rules)..."
    ufw --force reset >/dev/null 2>&1 || warn "ufw reset returned non-zero"
    ufw --force enable >/dev/null 2>&1 || warn "ufw enable returned non-zero"
    success "UFW reset and enabled"
    log "UFW reset and enabled"
}

# Menu
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
        if ! is_valid_port "$SSH_PORT"; then error "Invalid port"; log "ERROR: Invalid port $SSH_PORT"; exit 1; fi

        # Check port conflict first
        if ! check_port_conflict "$SSH_PORT"; then
            error "Port $SSH_PORT is in use by another process. Aborting."
            exit 1
        fi

        set_ssh_port "$SSH_PORT"

        read -rp "Do you want to reset UFW rules (recommended to avoid conflicts)? [y/N]: " yn
        if [[ "${yn,,}" == "y" ]]; then
            ufw_reset_with_backup
        else
            info "Skipping UFW reset"
            ufw --force enable >/dev/null 2>&1 || true
        fi

        ufw_allow "$SSH_PORT" tcp

        if restart_sshd; then
            success "SSH port changed to $SSH_PORT"
            log "SUCCESS: SSH port changed to $SSH_PORT by $USERNAME"
        else
            error "Failed to restart sshd after changing port. Rollback attempted. Check logs."
            log "ERROR: Failed to restart sshd after setting port $SSH_PORT"
            exit 1
        fi

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
        if restart_sshd; then
            success "Removed & blocked SSH port: $DEL_PORT"
            log "Removed & blocked SSH port: $DEL_PORT"
        else
            error "Failed to restart sshd after removing port $DEL_PORT. Rollback attempted."
            log "ERROR: Failed to restart sshd after removing port $DEL_PORT"
            exit 1
        fi

        echo " ➤ IPv4 : $SERVER_IPV4"
        echo " ➤ IPv6 : $SERVER_IPV6"
        ;;

    3|4|5|6|7|8)
        read -rp "Enter ports (commas/spaces/ranges allowed, e.g. 80,443 1000-1005): " PORT_INPUT
        mapfile -t PORTS < <(parse_ports "$PORT_INPUT")
        if [[ ${#PORTS[@]} -eq 0 ]]; then error "No valid ports parsed"; exit 1; fi

        case "$CHOICE" in
            3) proto_list=("tcp"); action="allow" ;;
            4) proto_list=("udp"); action="allow" ;;
            5) proto_list=("tcp" "udp"); action="allow" ;;
            6) proto_list=("tcp"); action="block" ;;
            7) proto_list=("udp"); action="block" ;;
            8) proto_list=("tcp" "udp"); action="block" ;;
        esac

        info "Parsed ports: ${PORTS[*]}"
        log "Operation: $action on ports ${PORTS[*]} proto ${proto_list[*]}"
        for p in "${PORTS[@]}"; do
            # port conflict check for allow (if adding an SSH-like port, optional)
            if [[ "$action" == "allow" ]]; then
                # allow regardless usually; but for SSH specifically, we might want to warn if in use
                if ! check_port_conflict "$p"; then
                    warn "Port $p is used by another process; you may not want to allow it. Continuing."
                fi
            fi

            for proto in "${proto_list[@]}"; do
                if [[ "$action" == "allow" ]]; then
                    ufw_allow "$p" "$proto"
                else
                    ufw_block "$p" "$proto"
                fi
            done
        done

        success "Operation complete for ports: ${PORTS[*]}"
        log "Complete: $action for ports ${PORTS[*]} proto ${proto_list[*]}"
        ;;

    9)
        read -rp "This will backup and RESET UFW (remove all rules). Continue? [y/N]: " yn
        if [[ "${yn,,}" == "y" ]]; then
            ufw_reset_with_backup
            log "User initiated UFW reset"
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

#!/bin/bash
set -euo pipefail

# SSH + UFW Port Manager v2.1 - OPTIMIZED
# - Auto-rollback on failed sshd restart
# - Port conflict detection (fast: single cached ss/netstat run)
# - IPv6 firewall awareness (UFW)
# - Logging (/var/log/sshport_manager.log) (reduced noisy logs)
# - Fast: avoids repeated slow commands (ss, ufw status numbered, slow curl)
#
# NOTE: Run as root.

LOGFILE="/var/log/sshport_manager.log"
BACKUP_DIR="/root/sshport_backups"
LAST_BACKUP=""
mkdir -p "$BACKUP_DIR"
touch "$LOGFILE"
chmod 600 "$LOGFILE"

# Colors / UI
info()    { printf " \e[1;34m→\e[0m %s\n" "$*"; }
success() { printf " \e[1;32m✔\e[0m %s\n" "$*"; }
warn()    { printf " \e[1;33m⚠\e[0m %s\n" "$*"; }
error()   { printf " \e[1;31m✖\e[0m %s\n" "$*"; }

# Logging (only key events)
log() {
    local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
    printf "%s %s\n" "$ts" "$*" >> "$LOGFILE"
}

# Quick IP detection with 1s timeout to avoid stalls
USERNAME=$(whoami)
SERVER_IPV4=$(curl -m 1 -s https://ipv4.icanhazip.com || echo "No IPv4 detected")
SERVER_IPV6=$(curl -m 1 -s https://ipv6.icanhazip.com || echo "No IPv6 detected")

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

    # Deduplicate
    declare -A seen=()
    for p in "${out[@]}"; do seen["$p"]=1; done
    for p in "${!seen[@]}"; do echo "$p"; done
}

# Check whether UFW has IPv6 enabled (quick config check)
ufw_ipv6_enabled() {
    if [[ -f /etc/default/ufw ]] && grep -Eqi '^IPV6=yes' /etc/default/ufw; then
        return 0
    fi
    if [[ -f /etc/ufw/ufw.conf ]] && grep -Eqi '^IPV6=yes' /etc/ufw/ufw.conf; then
        return 0
    fi
    return 1
}

# --- FAST port-list cache: run ss or netstat ONCE when needed ---
# Generate a cached listeners snapshot (called when needed)
_cached_port_snapshot=""
cached_port_snapshot() {
    if [[ -n "$_cached_port_snapshot" ]]; then
        printf "%s" "$_cached_port_snapshot"
        return 0
    fi

    # Try ss first (fast). Use single call for tcp+udp
    if command -v ss >/dev/null 2>&1; then
        _cached_port_snapshot=$(ss -tulnp 2>/dev/null || true)
        printf "%s" "$_cached_port_snapshot"
        return 0
    fi

    # Fallback to netstat if ss missing
    if command -v netstat >/dev/null 2>&1; then
        _cached_port_snapshot=$(netstat -tulpn 2>/dev/null || true)
        printf "%s" "$_cached_port_snapshot"
        return 0
    fi

    # If neither available, return empty
    _cached_port_snapshot=""
    printf ""
    return 0
}

# Port conflict detection using cached snapshot
# Returns 0 if free OR bound only by sshd; returns 1 if conflict detected
check_port_conflict() {
    local port=$1
    local snapshot
    snapshot=$(cached_port_snapshot)

    # Quick nothing-check
    if [[ -z "$snapshot" ]]; then
        # cannot determine; be conservative and allow (or you may want to abort)
        warn "Could not run ss/netstat to check port usage. Proceeding without conflict detection."
        log "WARN: Port conflict detection not available (ss/netstat missing)."
        return 0
    fi

    # Look for exact port occurrences (match :PORT or .PORT followed by space or end)
    # We'll examine first match if exists
    local match
    match=$(printf "%s\n" "$snapshot" | grep -E "[:.]${port}([[:space:]]|$)" | head -n1 || true)
    if [[ -z "$match" ]]; then
        return 0  # free
    fi

    # Try to extract pid=NNN or pid,program form
    # For ss output, pid=NNN, for netstat it's typically "PID/Program"
    local pid=""
    if echo "$match" | grep -q "pid="; then
        pid=$(echo "$match" | sed -n 's/.*pid=\([0-9]\+\),.*/\1/p' || true)
    else
        # netstat case: last column PID/Program
        pid=$(echo "$match" | awk '{ print $NF }' | cut -d'/' -f1 || true)
        if [[ "$pid" == "-" ]]; then pid=""; fi
    fi

    if [[ -z "$pid" ]]; then
        warn "Port $port appears used but PID unknown; aborting to be safe."
        log "CONFLICT: Port $port used but PID unknown in snapshot."
        return 1
    fi

    local pname
    pname=$(ps -p "$pid" -o comm= 2>/dev/null || true)

    # consider sshd allowed (if SSH already using the port)
    if [[ "$pname" == "sshd" || "$pname" == "sshd:" || "$pname" == "sshd" ]]; then
        return 0
    fi

    warn "Port $port is already used by PID=$pid ($pname)."
    log "CONFLICT: Port $port used by PID=$pid ($pname)"
    return 1
}

# Backup sshd_config (records LAST_BACKUP)
backup_sshd_config() {
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local src="/etc/ssh/sshd_config"
    local dst="$BACKUP_DIR/sshd_config.$ts"
    if cp -a "$src" "$dst"; then
        LAST_BACKUP="$dst"
        log "Backed up sshd_config to $dst"
        success "Backed up /etc/ssh/sshd_config → $dst"
        return 0
    else
        error "Failed to backup $src"
        log "ERROR: Failed to backup $src"
        return 1
    fi
}

# Rollback using LAST_BACKUP
rollback_last_sshd_backup() {
    if [[ -z "$LAST_BACKUP" || ! -f "$LAST_BACKUP" ]]; then
        error "No valid backup available for rollback!"
        log "ERROR: No valid LAST_BACKUP ($LAST_BACKUP)"
        return 1
    fi
    cp -a "$LAST_BACKUP" /etc/ssh/sshd_config
    log "Rollback: restored $LAST_BACKUP to /etc/ssh/sshd_config"
    warn "Rollback applied from $LAST_BACKUP"
    # Try restart once more
    if systemctl restart sshd 2>/dev/null; then
        success "sshd restarted after rollback"
        log "SUCCESS: sshd restarted after rollback"
        return 0
    fi
    if /etc/init.d/ssh restart 2>/dev/null; then
        success "sshd restarted via init.d after rollback"
        log "SUCCESS: sshd restarted via init.d after rollback"
        return 0
    fi
    error "Critical: Could not restart sshd after rollback. Manual intervention required!"
    log "CRITICAL: Could not restart sshd after rollback"
    return 2
}

# Update sshd_config port (remove all Port lines then add one)
set_ssh_port() {
    local port=$1
    backup_sshd_config

    # Remove all Port lines (commented or not)
    sed -i '/^[[:space:]]*#*[[:space:]]*Port[[:space:]]\+[0-9]\+/d' /etc/ssh/sshd_config

    # Add new Port line (single, clean)
    echo "Port $port" >> /etc/ssh/sshd_config
    log "sshd_config updated: Port $port"
    success "sshd_config updated to Port $port"
}

# Remove specific port entry
remove_ssh_port_entry() {
    local port=$1
    backup_sshd_config
    sed -i "/^[[:space:]]*#*[[:space:]]*Port[[:space:]]\+$port/d" /etc/ssh/sshd_config

    # If no Port line remains, ensure a commented default exists
    if ! grep -qE '^[[:space:]]*#*[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config; then
        if ! grep -q '^#Port 22' /etc/ssh/sshd_config; then
            sed -i '1i#Port 22' /etc/ssh/sshd_config
        fi
    fi
    success "Removed Port $port from sshd_config (if present)"
    log "Removed Port $port from sshd_config"
}

# Restart sshd safely; if fails attempt rollback
restart_sshd() {
    info "Restarting ssh service..."
    log "Attempt to restart sshd"
    if systemctl restart sshd 2>/dev/null; then
        success "sshd restarted"
        log "sshd restarted successfully"
        return 0
    fi
    warn "systemctl restart sshd failed; attempting init.d"
    if /etc/init.d/ssh restart 2>/dev/null; then
        success "sshd restarted via init.d"
        log "sshd restarted via init.d"
        return 0
    fi

    warn "sshd failed to restart; performing rollback"
    log "sshd restart failed; starting rollback"
    rollback_last_sshd_backup
    return 1
}

# UFW allow wrapper (fast)
ufw_allow() {
    local port=$1
    local proto=${2:-tcp}
    info "Applying UFW allow ${port}/${proto}"
    log "UFW allow ${port}/${proto}"
    # This will apply to both IPv4/IPv6 if UFW configured accordingly
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${port}/${proto} returned non-zero"
    if ! ufw_ipv6_enabled; then
        warn "UFW IPv6 appears disabled; IPv6 rule not guaranteed."
        log "WARN: UFW IPv6 disabled"
    fi
}

# UFW block wrapper (fast deletion attempt without status numbered)
ufw_block() {
    local port=$1
    local proto=${2:-tcp}
    info "Applying UFW deny ${port}/${proto}"
    log "UFW deny ${port}/${proto}"
    ufw deny "${port}/${proto}" >/dev/null 2>&1 || warn "ufw deny ${port}/${proto} returned non-zero"

    # Try to delete allow rule non-interactively (fast). ufw may prompt; echo 'y'
    # Use ufw delete allow "<port>/<proto>" which in many versions accepts direct rule deletion
    echo "y" | ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true

    if ! ufw_ipv6_enabled; then
        warn "UFW IPv6 appears disabled; IPv6 deny not applied"
        log "WARN: UFW IPv6 disabled; deny not applied for IPv6"
    fi
}

# Reset UFW with quick backups
ufw_reset_with_backup() {
    info "Backing up UFW rules..."
    local ts; ts=$(date +%Y%m%d_%H%M%S)
    cp -a /etc/ufw/user.rules "/etc/ufw/user.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/before.rules "/etc/ufw/before.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/after.rules "/etc/ufw/after.rules.$ts" 2>/dev/null || true
    cp -a /etc/ufw/user6.rules "/etc/ufw/user6.rules.$ts" 2>/dev/null || true
    log "UFW config backed up (ts=$ts)"
    info "Resetting UFW (this will remove all current rules)..."
    ufw --force reset >/dev/null 2>&1 || warn "ufw reset returned non-zero"
    ufw --force enable >/dev/null 2>&1 || warn "ufw enable returned non-zero"
    success "UFW reset and enabled"
    log "UFW reset and enabled"
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

# MAIN - fast path (cached snapshot used only when necessary)
print_menu
read -rp "Enter choice: " CHOICE

case "$CHOICE" in
    1)
        read -rp "Enter the new SSH port (single): " SSH_PORT
        if ! is_valid_port "$SSH_PORT"; then error "Invalid port"; log "ERROR: Invalid port $SSH_PORT"; exit 1; fi

        # Build snapshot once for conflict check
        cached_port_snapshot >/dev/null

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
            # ensure ufw enabled quickly
            ufw --force enable >/dev/null 2>&1 || true
        fi

        ufw_allow "$SSH_PORT" tcp

        if restart_sshd; then
            success "SSH port changed to $SSH_PORT"
            log "SUCCESS: SSH port changed to $SSH_PORT by $USERNAME"
        else
            error "Failed to restart sshd after changing port. Rollback attempted. Check $LOGFILE"
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

        # build port snapshot once
        cached_port_snapshot >/dev/null

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

        # build snapshot once for checks
        cached_port_snapshot >/dev/null

        for p in "${PORTS[@]}"; do
            if [[ "$action" == "allow" ]]; then
                # warn if port in use (but still allow)
                if ! check_port_conflict "$p"; then
                    warn "Port $p is used by another process; you may not want to allow it. Continuing."
                    log "WARN: Allowing port $p which is in use."
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
        log "Complete: $action for ports ${PORTS[*]}"
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

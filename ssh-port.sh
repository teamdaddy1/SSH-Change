#!/usr/bin/env bash
# SSH + UFW Port Manager v2.2 - Fixed & hardened
# - Requires: bash >= 4 recommended (we check and fallback where possible)
# - Auto-rollback on failed sshd restart
# - Port conflict detection (ss/netstat)
# - IPv6 firewall awareness (UFW)
# - Logging (/var/log or fallback /tmp)
# NOTE: Run as root.

set -euo pipefail

### Config
BACKUP_DIR="/root/sshport_backups"
LOGFILE="/var/log/sshport_manager.log"
FALLBACK_LOG="/tmp/sshport_manager.log"
LAST_BACKUP=""
mkdir -p "$BACKUP_DIR" 2>/dev/null || true

# Ensure running with bash (not /bin/sh)
if [ -z "${BASH_VERSION:-}" ]; then
  echo "This script must be run with bash (not sh). Try: bash $0" >&2
  exit 2
fi

# Bash version check (mapfile, assoc arrays require bash >=4)
bash_major=${BASH_VERSION%%.*}
if (( bash_major < 4 )); then
  echo "Warning: Bash >= 4 recommended. Some features may fallback." >&2
fi

# Root check
if (( EUID != 0 )); then
  echo "This script must be run as root. Use sudo or run as root." >&2
  exit 1
fi

# Ensure logfile writable; fallback if not
touch "$LOGFILE" >/dev/null 2>&1 || {
  LOGFILE="$FALLBACK_LOG"
  touch "$LOGFILE" >/dev/null 2>&1 || {
    echo "Cannot create log file at $LOGFILE or $FALLBACK_LOG. Exiting." >&2
    exit 1
  }
}
chmod 600 "$LOGFILE" >/dev/null 2>&1 || true

# UI helpers
info()    { printf " \e[1;34m→\e[0m %s\n" "$*"; }
success() { printf " \e[1;32m✔\e[0m %s\n" "$*"; }
warn()    { printf " \e[1;33m⚠\e[0m %s\n" "$*"; }
error()   { printf " \e[1;31m✖\e[0m %s\n" "$*"; }

log() {
  local ts; ts=$(date '+%Y-%m-%d %H:%M:%S')
  printf "%s %s\n" "$ts" "$*" >> "$LOGFILE"
}

# Quick IP detection with 1s timeout
USERNAME=$(whoami)
SERVER_IPV4=$(curl -m 1 -s https://ipv4.icanhazip.com || echo "No IPv4 detected")
SERVER_IPV6=$(curl -m 1 -s https://ipv6.icanhazip.com || echo "No IPv6 detected")

# Validate a single port number
is_valid_port() {
  local p=$1
  [[ $p =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

# Parse ports (comma, space, range)
# Output: one port per line
parse_ports() {
  local input="$*"
  local token
  local -a out=()
  input="${input//,/ }"
  for token in $input; do
    if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
      local start=${BASH_REMATCH[1]}
      local end=${BASH_REMATCH[2]}
      if (( start > end )); then local tmp=$start; start=$end; end=$tmp; fi
      for ((p=start; p<=end; p++)); do out+=("$p"); done
    elif is_valid_port "$token"; then
      out+=("$token")
    else
      warn "Skipping invalid token: $token"
      log "WARN: Skipping invalid token: $token"
    fi
  done

  # Deduplicate and print sorted (use assoc array if available)
  if (( bash_major >= 4 )); then
    declare -A seen=()
    for p in "${out[@]}"; do seen["$p"]=1; done
    local arr=()
    for p in "${!seen[@]}"; do arr+=("$p"); done
    IFS=$'\n' sorted=($(sort -n <<<"${arr[*]}"))
    unset IFS
    for p in "${sorted[@]}"; do echo "$p"; done
  else
    # fallback: naive dedupe & sort
    for p in "${out[@]}"; do echo "$p"; done | sort -n | awk '!seen[$0]++{print}'
  fi
}

# UFW IPv6 enabled check
ufw_ipv6_enabled() {
  if [[ -f /etc/default/ufw ]] && grep -Eqi '^IPV6=yes' /etc/default/ufw; then return 0; fi
  if [[ -f /etc/ufw/ufw.conf ]] && grep -Eqi '^IPV6=yes' /etc/ufw/ufw.conf; then return 0; fi
  return 1
}

# Cached snapshot (global)
_cached_port_snapshot=""
cached_port_snapshot() {
  if [[ -n "$_cached_port_snapshot" ]]; then
    printf "%s" "$_cached_port_snapshot"
    return 0
  fi
  if command -v ss >/dev/null 2>&1; then
    _cached_port_snapshot=$(ss -tulnp 2>/dev/null || true)
    printf "%s" "$_cached_port_snapshot"
    return 0
  fi
  if command -v netstat >/dev/null 2>&1; then
    _cached_port_snapshot=$(netstat -tulpn 2>/dev/null || true)
    printf "%s" "$_cached_port_snapshot"
    return 0
  fi
  _cached_port_snapshot=""
  printf ""
  return 0
}

# Check port conflict: returns 0 if free or bound by sshd, 1 if conflict
check_port_conflict() {
  local port=$1
  local snapshot
  snapshot=$(cached_port_snapshot)
  if [[ -z "$snapshot" ]]; then
    warn "Could not check ports (ss/netstat missing). Proceeding without conflict detection."
    log "WARN: Port conflict detection not available."
    return 0
  fi

  # Try to find a listening/socket line for that port
  # Use word boundary-ish pattern: :PORT or .PORT followed by non-digit
  local match
  match=$(printf "%s\n" "$snapshot" | grep -E "[:.]${port}([^0-9]|$)" | head -n1 || true)
  if [[ -z "$match" ]]; then
    return 0
  fi

  # Extract pid if present (ss format has pid=PID, netstat often shows last column PROG/PID)
  local pid=""
  if echo "$match" | grep -q 'pid='; then
    pid=$(echo "$match" | sed -n 's/.*pid=\([0-9]\+\),.*/\1/p' || true)
  else
    # try to take last field like "program/pid"
    pid=$(echo "$match" | awk '{ print $NF }' | awk -F'/' '{print $2}' || true)
    # sometimes PID is in different field; try to extract digits
    if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
      pid=$(echo "$match" | tr -s ' ' | cut -d' ' -f6 | tr -d '[:alpha:]/' || true)
      [[ "$pid" =~ ^[0-9]+$ ]] || pid=""
    fi
  fi

  if [[ -z "$pid" ]]; then
    warn "Port $port appears used but PID unknown; aborting to be safe."
    log "CONFLICT: Port $port used but PID unknown."
    return 1
  fi

  local pname; pname=$(ps -p "$pid" -o comm= 2>/dev/null || true)
  if [[ "$pname" == "sshd" || "$pname" == "sshd:" || "$pname" == "sshd" ]]; then
    return 0
  fi

  warn "Port $port is already used by PID=$pid ($pname)."
  log "CONFLICT: Port $port used by PID=$pid ($pname)."
  return 1
}

# Backup sshd_config
backup_sshd_config() {
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  local src="/etc/ssh/sshd_config"
  local dst="$BACKUP_DIR/sshd_config.$ts"
  if cp -a "$src" "$dst"; then
    LAST_BACKUP="$dst"
    log "Backup created: $dst"
    success "Backed up $src → $dst"
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
    log "ERROR: No LAST_BACKUP to rollback."
    return 1
  fi
  cp -a "$LAST_BACKUP" /etc/ssh/sshd_config
  log "Rollback applied from $LAST_BACKUP"
  warn "Rollback applied from $LAST_BACKUP"
  if command -v systemctl >/dev/null 2>&1 && systemctl restart sshd 2>/dev/null; then
    success "sshd restarted after rollback"
    log "SUCCESS: sshd restarted after rollback"
    return 0
  fi
  if /etc/init.d/ssh restart 2>/dev/null; then
    success "sshd restarted via init.d after rollback"
    log "SUCCESS: sshd restarted via init.d after rollback"
    return 0
  fi
  error "CRITICAL: Could not restart sshd after rollback - manual intervention required!"
  log "CRITICAL: Could not restart sshd after rollback"
  return 2
}

# Set SSH port - remove non-commented Port lines, preserve commented default
set_ssh_port() {
  local port=$1
  backup_sshd_config || return 1
  # delete only non-commented Port lines (keep commented defaults)
  sed -i '/^[[:space:]]*Port[[:space:]]\+[0-9]\+/d' /etc/ssh/sshd_config
  # ensure commented default exists
  if ! grep -q '^#Port 22' /etc/ssh/sshd_config; then
    sed -i '1i#Port 22' /etc/ssh/sshd_config
  fi
  # Append new Port line
  if ! grep -q "^Port ${port}" /etc/ssh/sshd_config; then
    echo "Port ${port}" >> /etc/ssh/sshd_config
  fi
  log "sshd_config set to Port $port"
  success "sshd_config updated to Port $port"
}

# Remove specific port entry (non-commented)
remove_ssh_port_entry() {
  local port=$1
  backup_sshd_config || return 1
  sed -i "/^[[:space:]]*Port[[:space:]]\+${port}/d" /etc/ssh/sshd_config
  if ! grep -qE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config; then
    if ! grep -q '^#Port 22' /etc/ssh/sshd_config; then
      sed -i '1i#Port 22' /etc/ssh/sshd_config
    fi
  fi
  success "Removed Port $port from sshd_config (if present)"
  log "Removed Port $port from sshd_config"
}

# Restart sshd safely (rollback if fails)
restart_sshd() {
  info "Restarting ssh service..."
  log "Attempting to restart sshd"
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl restart sshd 2>/dev/null; then
      success "sshd restarted (systemctl)"
      log "sshd restarted (systemctl)"
      return 0
    elif systemctl restart ssh 2>/dev/null; then
      success "ss restarted (systemctl ssh)"
      log "ss restarted (systemctl ssh)"
      return 0
    else
      warn "systemctl restart failed for sshd/ssh"
    fi
  fi

  if /etc/init.d/ssh restart 2>/dev/null; then
    success "sshd restarted via /etc/init.d/ssh"
    log "sshd restarted via /etc/init.d/ssh"
    return 0
  fi

  warn "sshd failed to restart; performing rollback"
  log "sshd restart failed; starting rollback"
  rollback_last_sshd_backup
  return 1
}

# UFW allow wrapper
ufw_allow() {
  local port=$1
  local proto=${2:-tcp}
  info "Applying UFW allow ${port}/${proto}"
  log "UFW allow ${port}/${proto}"
  ufw allow "${port}/${proto}" >/dev/null 2>&1 || warn "ufw allow ${port}/${proto} returned non-zero"
  if ! ufw_ipv6_enabled; then
    warn "UFW IPv6 appears disabled; IPv6 rule not guaranteed."
    log "WARN: UFW IPv6 disabled"
  fi
}

# UFW block wrapper (fast delete attempt)
ufw_block() {
  local port=$1
  local proto=${2:-tcp}
  info "Applying UFW deny ${port}/${proto}"
  log "UFW deny ${port}/${proto}"
  ufw deny "${port}/${proto}" >/dev/null 2>&1 || warn "ufw deny ${port}/${proto} returned non-zero"
  # Try to remove corresponding allow (non-interactive)
  printf "y\n" | ufw delete allow "${port}/${proto}" >/dev/null 2>&1 || true
  if ! ufw_ipv6_enabled; then
    warn "UFW IPv6 appears disabled; IPv6 deny not applied"
    log "WARN: UFW IPv6 disabled; deny not applied for IPv6"
  fi
}

# Reset UFW with backups
ufw_reset_with_backup() {
  info "Backing up UFW rules..."
  local ts; ts=$(date +%Y%m%d_%H%M%S)
  cp -a /etc/ufw/user.rules "/etc/ufw/user.rules.$ts" 2>/dev/null || true
  cp -a /etc/ufw/before.rules "/etc/ufw/before.rules.$ts" 2>/dev/null || true
  cp -a /etc/ufw/after.rules "/etc/ufw/after.rules.$ts" 2>/dev/null || true
  cp -a /etc/ufw/user6.rules "/etc/ufw/user6.rules.$ts" 2>/dev/null || true
  log "UFW backed up (ts=$ts)"
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

# Trap unexpected exit for logging
trap 'rc=$?; if (( rc != 0 )); then log "Script exited abnormally (code $rc)"; fi' EXIT

# MAIN
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
    # Use mapfile if available, otherwise use readarray fallback
    if declare -F mapfile >/dev/null 2>&1; then
      mapfile -t PORTS < <(parse_ports "$PORT_INPUT")
    else
      # fallback: read into array line by line
      IFS=$'\n' read -r -d '' -a PORTS < <(printf "%s\0" "$(parse_ports "$PORT_INPUT")") || true
    fi

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

    cached_port_snapshot >/dev/null

    for p in "${PORTS[@]}"; do
      if [[ "$action" == "allow" ]]; then
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

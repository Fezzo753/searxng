#!/usr/bin/env bash
# harden-host.sh - baseline hardening for Ubuntu 22.04/24.04 and Debian 12 hosts
# (the default images on Vultr). Idempotent: safe to re-run after changes.
#
# Usage (as root, on the host):
#   ADMIN_CIDR=203.0.113.10/32 ./harden-host.sh            # full run
#   ADMIN_CIDR=203.0.113.10/32 ./harden-host.sh --dry-run  # show what would change
#   ./harden-host.sh --only ssh,firewall                   # run selected steps
#
# Environment knobs (all optional unless noted):
#   ADMIN_CIDR        CIDR(s), comma separated, allowed to reach SSH. STRONGLY
#                     recommended. If unset, the IP of the current SSH session is
#                     used (/32) so you cannot lock yourself out.
#   SSH_PORT          default 22
#   ALLOW_HTTP        1 to also open port 80 to Cloudflare (only needed for
#                     HTTP-01 ACME; with a Cloudflare Origin CA cert you do not
#                     need it). default 0
#   EXTRA_TCP_RULES   extra ufw allows, "port:cidr,port:cidr" e.g.
#                     "51820:0.0.0.0/0" for WireGuard (udp use "51820/udp:...")
#   AUTO_REBOOT       unattended-upgrades reboots for kernel updates. default true
#   REBOOT_TIME       default 04:30 (server local time)
#   SKIP_DOCKER       1 to not touch /etc/docker/daemon.json
#
# Steps: updates ssh firewall fail2ban sysctl auditd services docker report
set -euo pipefail

DRY_RUN=0
ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --only) ONLY="$2"; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

SSH_PORT="${SSH_PORT:-22}"
ALLOW_HTTP="${ALLOW_HTTP:-0}"
AUTO_REBOOT="${AUTO_REBOOT:-true}"
REBOOT_TIME="${REBOOT_TIME:-04:30}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANGED=()
WARNINGS=()

log()  { printf '\e[1;34m[*]\e[0m %s\n' "$*"; }
ok()   { printf '\e[1;32m[+]\e[0m %s\n' "$*"; }
warn() { printf '\e[1;33m[!]\e[0m %s\n' "$*"; WARNINGS+=("$*"); }
die()  { printf '\e[1;31m[x]\e[0m %s\n' "$*" >&2; exit 1; }
run()  { if [[ $DRY_RUN -eq 1 ]]; then echo "    would run: $*"; else "$@"; fi; }

# write_file <path> <mode> ; content on stdin. Records change if differs.
write_file() {
  local path="$1" mode="$2" tmp
  tmp="$(mktemp)"; cat > "$tmp"
  if [[ -f "$path" ]] && cmp -s "$tmp" "$path"; then rm -f "$tmp"; return 1; fi
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "    would write $path:"; diff -u "$path" "$tmp" 2>/dev/null | sed 's/^/      /' || sed 's/^/      + /' "$tmp"
    rm -f "$tmp"
  else
    install -m "$mode" -D "$tmp" "$path"; rm -f "$tmp"
  fi
  CHANGED+=("$path"); return 0
}

want_step() { [[ -z "$ONLY" ]] || [[ ",$ONLY," == *",$1,"* ]]; }

preflight() {
  [[ $EUID -eq 0 ]] || die "run as root"
  . /etc/os-release
  case "${ID}-${VERSION_ID}" in
    ubuntu-22.04|ubuntu-24.04|debian-12|debian-13) ok "OS: $PRETTY_NAME" ;;
    *) warn "untested OS ($PRETTY_NAME); continuing" ;;
  esac
  if [[ -z "${ADMIN_CIDR:-}" ]]; then
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
      ADMIN_CIDR="${SSH_CONNECTION%% *}"
      [[ "$ADMIN_CIDR" == *:* ]] && ADMIN_CIDR="$ADMIN_CIDR/128" || ADMIN_CIDR="$ADMIN_CIDR/32"
      warn "ADMIN_CIDR not set; allowing SSH only from your current client $ADMIN_CIDR"
    else
      warn "ADMIN_CIDR not set and no SSH session detected; SSH will stay open to the world (fail2ban + keys-only still apply)"
      ADMIN_CIDR="any"
    fi
  fi
  export DEBIAN_FRONTEND=noninteractive
}

step_updates() {
  log "updates: apt upgrade + unattended-upgrades"
  run apt-get update -qq
  run apt-get -y -qq upgrade
  run apt-get -y -qq install unattended-upgrades apt-listchanges needrestart ca-certificates curl jq
  write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 <<'CONF' || true
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
  write_file /etc/apt/apt.conf.d/52unattended-upgrades-local 0644 <<CONF || true
// managed by harden-host.sh
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "${AUTO_REBOOT}";
Unattended-Upgrade::Automatic-Reboot-Time "${REBOOT_TIME}";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::SyslogEnable "true";
CONF
  # Debian's default origins only cover -security; Ubuntu's already include ESM.
  if [[ "$(. /etc/os-release; echo "$ID")" == debian ]]; then
    write_file /etc/apt/apt.conf.d/53unattended-origins-local 0644 <<'CONF' || true
Unattended-Upgrade::Origins-Pattern {
  "origin=Debian,codename=${distro_codename},label=Debian-Security";
  "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
  "origin=Debian,codename=${distro_codename}-updates";
};
CONF
  fi
  run systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
  # needrestart: restart services automatically after library upgrades
  write_file /etc/needrestart/conf.d/99-auto.conf 0644 <<'CONF' || true
$nrconf{restart} = 'a';
CONF
}

step_ssh() {
  log "ssh: keys only, no root password, sane limits"
  # Safety: never disable password auth unless at least one authorized_keys exists.
  local keys=0
  for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
    [[ -s "$f" ]] && keys=1
  done
  if [[ $keys -eq 0 ]]; then
    warn "no authorized_keys found on this host; leaving PasswordAuthentication unchanged to avoid lockout. Add a key and re-run."
    local pw_line="# PasswordAuthentication no   <- enable after adding an SSH key"
  else
    local pw_line="PasswordAuthentication no"
  fi
  mkdir -p /etc/ssh/sshd_config.d
  write_file /etc/ssh/sshd_config.d/99-hardening.conf 0600 <<CONF || true
# managed by harden-host.sh
Port ${SSH_PORT}
Protocol 2
${pw_line}
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
PermitEmptyPasswords no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
UseDNS no
LogLevel VERBOSE
# modern crypto only
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
CONF
  # Vultr cloud-init sometimes drops a file enabling password auth; neutralise it.
  if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]] && grep -q "PasswordAuthentication yes" /etc/ssh/sshd_config.d/50-cloud-init.conf; then
    run sed -i 's/^PasswordAuthentication yes/# PasswordAuthentication yes (disabled by harden-host.sh)/' /etc/ssh/sshd_config.d/50-cloud-init.conf
    CHANGED+=(/etc/ssh/sshd_config.d/50-cloud-init.conf)
  fi
  if [[ $DRY_RUN -eq 0 ]]; then
    sshd -t || die "sshd config test failed; not reloading. Fix /etc/ssh/sshd_config.d/99-hardening.conf"
    systemctl reload ssh 2>/dev/null || systemctl reload sshd
    ok "sshd reloaded (your current session is unaffected)"
  fi
}

step_firewall() {
  log "firewall: ufw default-deny, SSH from admin, 443 from Cloudflare only"
  run apt-get -y -qq install ufw
  if [[ $DRY_RUN -eq 1 ]]; then echo "    would configure ufw (deny in / allow out, ssh from $ADMIN_CIDR, 443 from Cloudflare)"; return; fi
  ufw --force reset >/dev/null
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  ufw logging low >/dev/null
  IFS=, read -ra cidrs <<<"$ADMIN_CIDR"
  for c in "${cidrs[@]}"; do
    if [[ "$c" == any ]]; then ufw allow "${SSH_PORT}/tcp" comment 'ssh (open - set ADMIN_CIDR!)' >/dev/null
    else ufw allow from "$c" to any port "$SSH_PORT" proto tcp comment 'ssh admin' >/dev/null; fi
  done
  if [[ -n "${EXTRA_TCP_RULES:-}" ]]; then
    IFS=, read -ra extras <<<"$EXTRA_TCP_RULES"
    for e in "${extras[@]}"; do
      local port="${e%%:*}" src="${e#*:}" proto=tcp
      [[ "$port" == */udp ]] && { proto=udp; port="${port%/udp}"; }
      ufw allow from "$src" to any port "$port" proto "$proto" comment 'extra' >/dev/null
    done
  fi
  # Cloudflare-only web ports, refreshed daily by cloudflare-allowlist.sh
  local ports=443; [[ "$ALLOW_HTTP" == 1 ]] && ports="80,443"
  install -m 0755 "$HERE/cloudflare-allowlist.sh" /usr/local/sbin/cloudflare-allowlist.sh
  PORTS="$ports" /usr/local/sbin/cloudflare-allowlist.sh --install-timer
  ufw --force enable >/dev/null
  ok "ufw enabled: $(ufw status | grep -c ALLOW) allow rules"
  CHANGED+=(ufw)
}

step_fail2ban() {
  log "fail2ban: sshd + recidive only (web traffic is behind Cloudflare; banning there would ban Cloudflare IPs)"
  run apt-get -y -qq install fail2ban
  local ignore="127.0.0.1/8 ::1"
  [[ "$ADMIN_CIDR" != any ]] && ignore="$ignore ${ADMIN_CIDR//,/ }"
  write_file /etc/fail2ban/jail.d/99-hardening.local 0644 <<CONF || true
[DEFAULT]
ignoreip = ${ignore}
bantime  = 1h
findtime = 10m
maxretry = 4
backend  = systemd
banaction = ufw

[sshd]
enabled = true
port    = ${SSH_PORT}
mode    = aggressive

[recidive]
enabled  = true
logpath  = /var/log/fail2ban.log
bantime  = 1w
findtime = 1d
maxretry = 3
CONF
  run systemctl enable --now fail2ban >/dev/null
  [[ $DRY_RUN -eq 0 ]] && systemctl restart fail2ban
}

step_sysctl() {
  log "sysctl: network and kernel hardening"
  local fwd="net.ipv4.ip_forward = 0"
  if command -v docker >/dev/null 2>&1 || [[ -d /etc/docker ]]; then
    fwd="# ip_forward left enabled: Docker present"
  fi
  write_file /etc/sysctl.d/99-hardening.conf 0644 <<CONF || true
# managed by harden-host.sh
${fwd}
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
CONF
  run sysctl --system >/dev/null
}

step_auditd() {
  log "auditd: watch identity, sudo and sshd config changes"
  run apt-get -y -qq install auditd audispd-plugins
  write_file /etc/audit/rules.d/99-hardening.rules 0640 <<'CONF' || true
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /root/.ssh/ -p wa -k sshkeys
-w /etc/cron.d/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /usr/local/sbin/ -p wa -k localbin
-w /var/log/auth.log -p wa -k authlog
-a always,exit -F arch=b64 -S setuid,setgid,setresuid,setresgid -F auid>=1000 -F auid!=unset -k privesc
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k rootcmd
-w /sbin/insmod -p x -k modules
-w /sbin/modprobe -p x -k modules
CONF
  run systemctl enable --now auditd >/dev/null 2>&1 || true
  [[ $DRY_RUN -eq 0 ]] && (augenrules --load >/dev/null 2>&1 || service auditd restart || true)
}

step_services() {
  log "services: journald limits, apparmor, remove unneeded daemons"
  write_file /etc/systemd/journald.conf.d/99-hardening.conf 0644 <<'CONF' || true
[Journal]
Storage=persistent
SystemMaxUse=500M
Compress=yes
CONF
  run systemctl restart systemd-journald
  run apt-get -y -qq install apparmor apparmor-utils
  run systemctl enable --now apparmor >/dev/null 2>&1 || true
  for svc in avahi-daemon cups rpcbind nfs-server telnet.socket; do
    if systemctl list-unit-files "$svc" >/dev/null 2>&1 && systemctl is-enabled "$svc" >/dev/null 2>&1; then
      run systemctl disable --now "$svc"; CHANGED+=("disabled $svc")
    fi
  done
  # umask and login hardening
  write_file /etc/profile.d/99-umask.sh 0644 <<'CONF' || true
umask 027
CONF
  if grep -q '^PASS_MAX_DAYS' /etc/login.defs; then :; fi
  # core dumps off
  write_file /etc/security/limits.d/99-nocore.conf 0644 <<'CONF' || true
* hard core 0
CONF
  write_file /etc/systemd/coredump.conf.d/99-off.conf 0644 <<'CONF' || true
[Coredump]
Storage=none
ProcessSizeMax=0
CONF
}

step_docker() {
  [[ "${SKIP_DOCKER:-0}" == 1 ]] && return
  command -v docker >/dev/null 2>&1 || { log "docker: not installed, skipping"; return; }
  log "docker: bind published ports to loopback by default, log limits, no-new-privileges"
  # Docker inserts its own iptables rules AHEAD of ufw, so "-p 8080:8080" is
  # reachable from the internet regardless of ufw. Defaulting the publish
  # address to 127.0.0.1 closes that hole: only nginx on the host (or a
  # Cloudflare Tunnel) reaches containers.
  local current="{}"; [[ -f /etc/docker/daemon.json ]] && current="$(cat /etc/docker/daemon.json)"
  local desired
  desired="$(jq -S '. + {"ip":"127.0.0.1","live-restore":true,"no-new-privileges":true,"log-driver":"json-file","log-opts":{"max-size":"20m","max-file":"5"},"userland-proxy":false}' <<<"$current")"
  if write_file /etc/docker/daemon.json 0644 <<<"$desired"; then
    warn "Docker daemon.json changed. Containers that must be reachable from the host only are fine; anything that MUST be public needs an explicit '-p 0.0.0.0:PORT:PORT' (and a ufw rule). Restart docker to apply: systemctl restart docker  (live-restore keeps containers running)."
  fi
  # catch already-exposed containers
  local exposed
  exposed="$(docker ps --format '{{.Names}} {{.Ports}}' 2>/dev/null | grep -E '0\.0\.0\.0:|\[::\]:' || true)"
  [[ -n "$exposed" ]] && warn "containers currently published on all interfaces (reachable despite ufw):"$'\n'"$exposed"
}

step_report() {
  log "report"
  echo
  echo "Listening sockets reachable from outside (not bound to loopback):"
  ss -Hltnup 2>/dev/null | awk '$5 !~ /^(127\.|\[::1\]|\[::ffff:127)/ {print "   ", $1, $5, $7}' | sort -u
  echo
  echo "Reboot required: $([[ -f /var/run/reboot-required ]] && echo YES || echo no)"
  echo "Changed: ${#CHANGED[@]} item(s)"; printf '    %s\n' "${CHANGED[@]:-none}"
  if [[ ${#WARNINGS[@]} -gt 0 ]]; then echo; echo "Warnings:"; printf '  - %s\n' "${WARNINGS[@]}"; fi
}

preflight
for s in updates ssh firewall fail2ban sysctl auditd services docker report; do
  want_step "$s" && "step_$s"
done

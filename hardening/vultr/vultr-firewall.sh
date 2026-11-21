#!/usr/bin/env bash
# vultr-firewall.sh - manage a Vultr Firewall Group (network-edge firewall,
# enforced before packets reach the VM) that allows:
#   * HTTPS (and optionally HTTP) only from Cloudflare's edge ranges
#   * SSH only from your admin CIDR(s)
#   * ICMP (needed for IPv6 to work properly, harmless for IPv4)
# Everything else inbound is dropped by Vultr. This is defense in depth on top
# of ufw on the host; it also protects hosts where ufw is misconfigured or
# where Docker punched through it.
#
# Requires: curl, jq, VULTR_API_KEY (Account > API; restrict the key's access
# to your admin IP in the Vultr panel).
#
#   ./vultr-firewall.sh list
#   ./vultr-firewall.sh create  --name web-cloudflare --admin-cidr 203.0.113.10/32[,...] [--http] [--ssh-port 22]
#   ./vultr-firewall.sh sync    <group-id> [--http] [--admin-cidr ...] [--ssh-port 22]   # re-sync rules (run monthly / on CF changes)
#   ./vultr-firewall.sh attach  <group-id> <instance-id>|all
#   ./vultr-firewall.sh instances        # show instances and their current group
set -euo pipefail
API=https://api.vultr.com/v2
: "${VULTR_API_KEY:?set VULTR_API_KEY}"

api() { # api METHOD PATH [json]
  local m="$1" p="$2" d="${3:-}"
  if [[ -n "$d" ]]; then
    curl -fsS -X "$m" "$API$p" -H "Authorization: Bearer $VULTR_API_KEY" -H 'Content-Type: application/json' --data "$d"
  else
    curl -fsS -X "$m" "$API$p" -H "Authorization: Bearer $VULTR_API_KEY"
  fi
}

cmd="${1:-help}"; shift || true
NAME=""; ADMIN_CIDR=""; HTTP=0; SSH_PORT=22; GROUP=""; TARGET=""
case "$cmd" in
  create) ;;
  sync|attach) GROUP="${1:?group id}"; shift ;;
esac
[[ $cmd == attach ]] && { TARGET="${1:?instance id or all}"; shift; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="$2"; shift ;;
    --admin-cidr) ADMIN_CIDR="$2"; shift ;;
    --http) HTTP=1 ;;
    --ssh-port) SSH_PORT="$2"; shift ;;
    *) echo "unknown arg $1" >&2; exit 2 ;;
  esac; shift
done

fetch_cf() {
  curl -fsS --max-time 20 https://www.cloudflare.com/ips-v4 | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]+$'
  curl -fsS --max-time 20 https://www.cloudflare.com/ips-v6 | grep -E '^[0-9a-fA-F:]+/[0-9]+$'
}

add_rule() { # add_rule type proto subnet size port notes
  local sub="$3"
  api POST "/firewalls/$GROUP/rules" "$(jq -nc --arg t "$1" --arg p "$2" --arg s "$sub" --argjson z "$4" --arg port "$5" --arg n "$6" \
    '{ip_type:$t, protocol:$p, subnet:$s, subnet_size:$z, port:$port, notes:$n}')" >/dev/null
}

sync_rules() {
  echo "syncing rules in group $GROUP"
  # wipe managed rules (notes prefixed "managed:") then re-add
  local ids
  ids="$(api GET "/firewalls/$GROUP/rules?per_page=500" | jq -r '.firewall_rules[] | select(.notes|startswith("managed:")) | .id')"
  for id in $ids; do api DELETE "/firewalls/$GROUP/rules/$id"; done
  local n=0
  # SSH from admin
  if [[ -n "$ADMIN_CIDR" ]]; then
    IFS=, read -ra cidrs <<<"$ADMIN_CIDR"
    for c in "${cidrs[@]}"; do
      local t=v4; [[ "$c" == *:* ]] && t=v6
      add_rule "$t" tcp "${c%/*}" "${c#*/}" "$SSH_PORT" "managed:ssh-admin"; n=$((n+1))
    done
  else
    echo "note: no --admin-cidr given; SSH rule not (re)created" >&2
  fi
  # ICMP (IPv6 needs it; PMTU discovery for v4)
  add_rule v4 icmp 0.0.0.0 0 "" "managed:icmp"; add_rule v6 icmp :: 0 "" "managed:icmp"; n=$((n+2))
  # web from Cloudflare only
  local ports="443"; [[ $HTTP -eq 1 ]] && ports="80 443"
  while read -r cidr; do
    [[ -z "$cidr" ]] && continue
    local t=v4; [[ "$cidr" == *:* ]] && t=v6
    for p in $ports; do add_rule "$t" tcp "${cidr%/*}" "${cidr#*/}" "$p" "managed:cloudflare"; n=$((n+1)); done
  done < <(fetch_cf)
  echo "$n rules in place. (Vultr caps rules per group; if adds failed above, drop --http or split groups.)"
}

case "$cmd" in
  list)
    api GET /firewalls | jq -r '.firewall_groups[] | "\(.id)  \(.description)  rules=\(.rule_count) instances=\(.instance_count)"' ;;
  instances)
    api GET "/instances?per_page=500" | jq -r '.instances[] | "\(.id)  \(.label // "-")  \(.main_ip)  fw=\(.firewall_group_id // "none")"' ;;
  create)
    : "${NAME:?--name required}"; : "${ADMIN_CIDR:?--admin-cidr required (your IP/32; otherwise SSH is unreachable once attached)}"
    GROUP="$(api POST /firewalls "$(jq -nc --arg d "$NAME" '{description:$d}')" | jq -r .firewall_group.id)"
    echo "created group $GROUP"; sync_rules
    echo "next: $0 attach $GROUP <instance-id>|all" ;;
  sync) sync_rules ;;
  attach)
    if [[ "$TARGET" == all ]]; then
      ids="$(api GET "/instances?per_page=500" | jq -r '.instances[].id')"
    else ids="$TARGET"; fi
    for i in $ids; do
      api PATCH "/instances/$i" "$(jq -nc --arg g "$GROUP" '{firewall_group_id:$g}')" >/dev/null && echo "attached $GROUP -> $i"
    done ;;
  *) sed -n '2,20p' "$0" ;;
esac

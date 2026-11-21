#!/usr/bin/env bash
# external-check.sh - verify from the outside that a site is actually protected.
# Run from your laptop or any box that is NOT the server. Only point it at
# hosts you own.
#
#   ./external-check.sh search.example.com                 # DNS/TLS/header checks
#   ./external-check.sh search.example.com 45.76.1.2       # + origin exposure checks
#
# Checks: DNS resolves to Cloudflare; HTTP->HTTPS redirect; TLS 1.0/1.1 rejected;
# HSTS and security headers present; server banner hidden; origin IP refuses
# direct HTTPS (Cloudflare-only firewall / Authenticated Origin Pulls); common
# admin/database ports closed on the origin.
set -uo pipefail
host="${1:?hostname}"; origin="${2:-}"
pass=0; fail=0
ok()   { printf '  \e[32mPASS\e[0m %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  \e[31mFAIL\e[0m %s\n' "$*"; fail=$((fail+1)); }
info() { printf '  \e[34minfo\e[0m %s\n' "$*"; }

echo "== $host =="
cf4="$(curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 2>/dev/null)" || cf4=""
ips="$(getent ahostsv4 "$host" | awk '{print $1}' | sort -u)"
if [[ -z "$ips" ]]; then bad "does not resolve"; else
  in_cf=1
  for ip in $ips; do
    hit=0
    for cidr in $cf4; do
      python3 - "$ip" "$cidr" <<'PY' && { hit=1; break; }
import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)
PY
    done
    [[ $hit -eq 1 ]] || in_cf=0
  done
  [[ $in_cf -eq 1 ]] && ok "A records are Cloudflare edge IPs ($(tr '\n' ' ' <<<"$ips"))" || bad "A record(s) NOT on Cloudflare: $(tr '\n' ' ' <<<"$ips") - origin exposed or grey-clouded"
fi

code="$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' --max-time 10 "http://$host/" 2>/dev/null)"
[[ "$code" == 30* && "$code" == *https://* ]] && ok "HTTP redirects to HTTPS" || bad "HTTP does not redirect to HTTPS ($code)"

for v in tls1 tls1_1; do
  if openssl s_client -connect "$host:443" -servername "$host" -$v </dev/null >/dev/null 2>&1; then bad "$v accepted"; else ok "$v rejected"; fi
done
openssl s_client -connect "$host:443" -servername "$host" -tls1_3 </dev/null >/dev/null 2>&1 && ok "TLS 1.3 offered" || bad "TLS 1.3 not offered"

hdrs="$(curl -sSI --max-time 10 "https://$host/" 2>/dev/null | tr -d '\r')"
chk() { grep -qi "^$1:" <<<"$hdrs" && ok "header $1" || bad "missing header $1"; }
chk strict-transport-security; chk x-content-type-options; chk referrer-policy; chk content-security-policy; chk x-frame-options
srv="$(grep -i '^server:' <<<"$hdrs" | cut -d' ' -f2-)"
[[ "$srv" == cloudflare* ]] && ok "server header is cloudflare (origin banner hidden)" || info "server header: ${srv:-none}"
grep -qi '^x-powered-by:' <<<"$hdrs" && bad "x-powered-by leaks stack" || ok "no x-powered-by"
grep -qi '^cf-ray:' <<<"$hdrs" && ok "served via Cloudflare (cf-ray)" || bad "no cf-ray header: traffic is not going through Cloudflare"

if [[ -n "$origin" ]]; then
  echo "== origin $origin =="
  # direct HTTPS with the real hostname should be refused (firewall) or fail the
  # client-cert check (AOP: 400/403/connection error). 200 means bypass works.
  oc="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 8 -k --resolve "$host:443:$origin" "https://$host/" 2>/dev/null)"
  case "$oc" in
    000) ok "direct HTTPS to origin refused (firewall)" ;;
    400|403|495|496) ok "direct HTTPS to origin rejected by origin ($oc) - AOP/host check" ;;
    *) bad "direct HTTPS to origin returned $oc - Cloudflare can be bypassed" ;;
  esac
  for p in 21 22 23 25 80 443 2375 2376 3000 3306 5432 6379 8000 8080 8443 9000 9200 27017; do
    if timeout 3 bash -c "exec 3<>/dev/tcp/$origin/$p" 2>/dev/null; then
      case $p in 443) info "port $p open (expected, Cloudflare-only?)";; 22) info "port 22 open (should be admin-IP only)";; *) bad "port $p open on origin";; esac
    fi
  done
  ok "port scan done (closed ports not listed)"
fi
echo; echo "$pass passed, $fail failed"
[[ $fail -eq 0 ]]

#!/usr/bin/env bash
# harden-zone.sh - audit and apply a secure baseline to Cloudflare zones.
#
#   CLOUDFLARE_API_TOKEN=... ./harden-zone.sh audit            # all zones the token can see
#   CLOUDFLARE_API_TOKEN=... ./harden-zone.sh audit example.com
#   CLOUDFLARE_API_TOKEN=... ./harden-zone.sh apply example.com other.org
#
# Token permissions (create at dash.cloudflare.com/profile/api-tokens, scope it
# to the zones you want): Zone:Read, Zone Settings:Edit, DNS:Read, SSL and
# Certificates:Edit, Zone WAF:Edit, Bot Management:Edit, DNSSEC:Edit (part of
# Zone:Edit on older UIs).
#
# What "apply" sets (each can be skipped with the env var shown):
#   ssl=strict (ORIGIN_SSL_MODE=full to relax; strict needs a valid cert on the
#     origin - use a free Cloudflare Origin CA cert, 15-year validity)
#   always_use_https=on, automatic_https_rewrites=on, min_tls_version=1.2,
#   tls_1_3=on, opportunistic_encryption=on, 0-RTT off
#   HSTS on (max-age 6 months, no includeSubDomains/preload) SKIP_HSTS=1
#   browser_check=on, security_level=medium, email_obfuscation=on
#   Authenticated Origin Pulls on (zone side; origin must verify, see nginx conf) SKIP_AOP=1
#   Bot Fight Mode on                                           SKIP_BOTS=1
#   DNSSEC enabled (prints DS record to set at your registrar)  SKIP_DNSSEC=1
#   WAF: Cloudflare Managed Ruleset deployed on paid plans      SKIP_WAF=1
#        (+ OWASP Core Ruleset with DEPLOY_OWASP=1). Free plans already get the
#        Free Managed Ruleset automatically.
# Audit also lists DNS records that are NOT proxied (grey cloud) - those leak
# your origin IPs and bypass every Cloudflare protection.
set -euo pipefail
: "${CLOUDFLARE_API_TOKEN:?set CLOUDFLARE_API_TOKEN}"
API=https://api.cloudflare.com/client/v4
ORIGIN_SSL_MODE="${ORIGIN_SSL_MODE:-strict}"

cf() { # cf METHOD PATH [json]  -> prints .result or dies with CF errors
  local m="$1" p="$2" d="${3:-}" out
  if [[ -n "$d" ]]; then
    out="$(curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" -H 'Content-Type: application/json' --data "$d")"
  else
    out="$(curl -sS -X "$m" "$API$p" -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN")"
  fi
  if [[ "$(jq -r .success <<<"$out")" != true ]]; then
    echo "    API error on $m $p: $(jq -c '.errors' <<<"$out")" >&2; return 1
  fi
  jq -c '.result' <<<"$out"
}

red()   { printf '\e[31m%s\e[0m' "$*"; }
green() { printf '\e[32m%s\e[0m' "$*"; }

# desired zone settings: name=value (value is JSON)
declare -A WANT=(
  [ssl]="\"$ORIGIN_SSL_MODE\""
  [always_use_https]='"on"'
  [automatic_https_rewrites]='"on"'
  [min_tls_version]='"1.2"'
  [tls_1_3]='"on"'
  [opportunistic_encryption]='"on"'
  [0rtt]='"off"'
  [browser_check]='"on"'
  [security_level]='"medium"'
  [email_obfuscation]='"on"'
  [ipv6]='"on"'
)
[[ "${SKIP_AOP:-0}" == 1 ]]  || WANT[tls_client_auth]='"on"'
[[ "${SKIP_HSTS:-0}" == 1 ]] || WANT[security_header]='{"strict_transport_security":{"enabled":true,"max_age":15552000,"include_subdomains":false,"preload":false,"nosniff":true}}'

zone_ids() {
  if [[ $# -eq 0 ]]; then
    cf GET "/zones?per_page=50&status=active" | jq -r '.[] | "\(.id) \(.name) \(.plan.legacy_id // .plan.name)"'
  else
    for z in "$@"; do cf GET "/zones?name=$z" | jq -r '.[] | "\(.id) \(.name) \(.plan.legacy_id // .plan.name)"'; done
  fi
}

audit_zone() { # id name plan
  local id="$1" name="$2" plan="$3" settings bad=0
  echo; echo "== $name ($plan) =="
  settings="$(cf GET "/zones/$id/settings")"
  for k in "${!WANT[@]}"; do
    local cur want
    cur="$(jq -c --arg k "$k" '.[] | select(.id==$k) | .value' <<<"$settings")"
    want="${WANT[$k]}"
    if [[ "$k" == security_header ]]; then
      cur="$(jq -c '.strict_transport_security | {enabled, max_age}' <<<"${cur:-null}")"
      want='{"enabled":true,"max_age":15552000}'
    fi
    if [[ "$cur" == "$want" ]]; then printf '  %-26s %s\n' "$k" "$(green "$cur")"
    else printf '  %-26s %s  (want %s)\n' "$k" "$(red "${cur:-unset}")" "$want"; bad=$((bad+1)); fi
  done
  local dnssec; dnssec="$(cf GET "/zones/$id/dnssec" | jq -r .status)"
  [[ "$dnssec" == active ]] && printf '  %-26s %s\n' dnssec "$(green active)" || { printf '  %-26s %s\n' dnssec "$(red "$dnssec")"; bad=$((bad+1)); }
  local bots; bots="$(cf GET "/zones/$id/bot_management" 2>/dev/null | jq -r '.fight_mode // .sbfm_definitely_automated // "n/a"')"
  [[ "$bots" == true || "$bots" == block ]] && printf '  %-26s %s\n' bot_fight_mode "$(green "$bots")" || { printf '  %-26s %s\n' bot_fight_mode "$(red "$bots")"; bad=$((bad+1)); }
  local waf; waf="$(cf GET "/zones/$id/rulesets/phases/http_request_firewall_managed/entrypoint" 2>/dev/null | jq -r '[.rules[]?.action_parameters.id] | length' || echo 0)"
  if [[ "$plan" == free ]]; then printf '  %-26s %s\n' waf_managed "$(green "free managed ruleset (automatic)")"
  elif [[ "${waf:-0}" -gt 0 ]]; then printf '  %-26s %s\n' waf_managed "$(green "$waf managed ruleset(s) deployed")"
  else printf '  %-26s %s\n' waf_managed "$(red none)"; bad=$((bad+1)); fi
  # unproxied records expose origin IPs
  local unprox
  unprox="$(cf GET "/zones/$id/dns_records?per_page=500" | jq -r '.[] | select((.type=="A" or .type=="AAAA" or .type=="CNAME") and .proxied==false) | "    \(.type) \(.name) -> \(.content)"')"
  if [[ -n "$unprox" ]]; then echo "  $(red 'unproxied records (origin exposed, no WAF):')"; echo "$unprox"; bad=$((bad+1))
  else echo "  $(green 'all A/AAAA/CNAME records proxied')"; fi
  echo "  -> $bad finding(s)"
}

apply_zone() {
  local id="$1" name="$2" plan="$3"
  echo; echo "== applying to $name ($plan) =="
  for k in "${!WANT[@]}"; do
    if cf PATCH "/zones/$id/settings/$k" "{\"value\":${WANT[$k]}}" >/dev/null; then echo "  set $k"; fi
  done
  if [[ "${SKIP_BOTS:-0}" != 1 ]]; then
    if [[ "$plan" == free ]]; then cf PUT "/zones/$id/bot_management" '{"fight_mode":true}' >/dev/null && echo "  bot fight mode on"
    else cf PUT "/zones/$id/bot_management" '{"sbfm_definitely_automated":"block","sbfm_verified_bots":"allow","sbfm_static_resource_protection":false,"optimize_wordpress":false}' >/dev/null && echo "  super bot fight mode: block definitely-automated"; fi || true
  fi
  if [[ "${SKIP_DNSSEC:-0}" != 1 ]]; then
    local ds; ds="$(cf PATCH "/zones/$id/dnssec" '{"status":"active"}')" && {
      echo "  dnssec: $(jq -r .status <<<"$ds")"
      [[ "$(jq -r .status <<<"$ds")" != active ]] && echo "    add this DS record at your registrar (Cloudflare Registrar does it automatically):" && jq -r '"    DS \(.key_tag) \(.algorithm) \(.digest_type) \(.digest)"' <<<"$ds"
    } || true
  fi
  if [[ "${SKIP_WAF:-0}" != 1 && "$plan" != free ]]; then
    local rules='[{"action":"execute","action_parameters":{"id":"efb7b8c949ac4650a09736fc376e9aee"},"expression":"true","description":"Cloudflare Managed Ruleset"}'
    [[ "${DEPLOY_OWASP:-0}" == 1 ]] && rules+=',{"action":"execute","action_parameters":{"id":"4814384a9e5d4991b9815dcfc25d2f1f"},"expression":"true","description":"OWASP Core Ruleset"}'
    rules+=']'
    local existing; existing="$(cf GET "/zones/$id/rulesets/phases/http_request_firewall_managed/entrypoint" 2>/dev/null | jq -r '[.rules[]?] | length' || echo 0)"
    if [[ "${existing:-0}" -eq 0 ]]; then
      cf PUT "/zones/$id/rulesets/phases/http_request_firewall_managed/entrypoint" "{\"rules\":$rules}" >/dev/null && echo "  WAF managed ruleset(s) deployed"
    else echo "  WAF: $existing managed rule(s) already deployed, left as is"; fi
  fi
  audit_zone "$id" "$name" "$plan"
}

cmd="${1:-audit}"; shift || true
case "$cmd" in
  audit) while read -r id name plan; do audit_zone "$id" "$name" "$plan"; done < <(zone_ids "$@") ;;
  apply) while read -r id name plan; do apply_zone "$id" "$name" "$plan"; done < <(zone_ids "$@") ;;
  *) sed -n '2,30p' "$0" ;;
esac

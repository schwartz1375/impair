#!/usr/bin/env bash
# Independent expiry test on a disposable systemd Linux VM. Creates only a dummy link.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
binary=$(realpath "${1:?Usage: sudo tests/watchdog.sh /absolute/path/to/impair}")
state_dir=$(mktemp -d /run/impair-watchdog.XXXXXXXX)
test_iface="imwd${RANDOM}${RANDOM}"
test_iface=${test_iface:0:15}
created=0
cleanup() {
  "$binary" stop --state-dir "$state_dir" || true
  if [[ $created == 1 ]]; then ip link delete dev "$test_iface" || true; fi
  rm -rf -- "$state_dir"
}
trap cleanup EXIT
ip link add name "$test_iface" type dummy
created=1
ip link set dev "$test_iface" up
cat > "$state_dir/profile.json" <<JSON
{"version":1,"name":"watchdog-test","rules":[{"interface":"$test_iface","direction":"egress","match":{},"impairment":{"delay":"1ms"}}]}
JSON
"$binary" apply --profile "$state_dir/profile.json" --state-dir "$state_dir" --duration 5s
for attempt in {1..20}; do
  if [[ ! -f "$state_dir/active.json" ]]; then
    if tc qdisc show dev "$test_iface" | grep -q '7a00:'; then
      echo 'FAIL: timer cleared journal but left impairment.' >&2
      exit 1
    fi
    echo 'PASS: independent systemd expiry removed experiment.'
    exit 0
  fi
  sleep 1
done
echo 'FAIL: experiment did not expire; inspect journalctl -u "impair-*".' >&2
exit 1

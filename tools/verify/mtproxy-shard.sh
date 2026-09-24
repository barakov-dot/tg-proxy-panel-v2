#!/usr/bin/env bash
# Verifies on a real server (FINDINGS.md, items 1, 7 and 8):
#   - pinned official MTProxy builds from the checksum-verified archive;
#   - one process accepts 16 -S secrets and 16 -H ports, 17 secrets abort;
#   - run as an unprivileged user, -u is ignored (even a nonexistent user);
#   - with --http-stats the stats port answers /stats on loopback;
#   - RSS of one shard with -M 1 and with -M 0 (idle), middle-end connectivity.
# Everything lives in a temporary directory and is removed on exit.
# Usage: sudo bash tools/verify/mtproxy-shard.sh [--install-deps]
set -euo pipefail

mtproxy_commit=f36d8af769ffaeac36978d38c2c0f6d1104c2137
mtproxy_checksum=919795c416b870670841a21d1930ad97a24c7b84b9eb8c6f9e3de32f2fdf4655
stats_port=29890
first_port=29900
idle_seconds=30

if [[ "${EUID}" -ne 0 ]]; then
	echo "FAIL: запустите от root"
	exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
	echo "FAIL: нужен x86_64"
	exit 1
fi
if [[ "${1:-}" == "--install-deps" ]]; then
	DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		ca-certificates curl build-essential libssl-dev zlib1g-dev iproute2
fi
missing=()
for required in curl make gcc ss runuser setpriv sha256sum; do
	command -v "$required" >/dev/null 2>&1 || missing+=("$required")
done
if [[ ! -e /usr/include/openssl/ssl.h ]] || [[ ! -e /usr/include/zlib.h ]]; then
	missing+=("libssl-dev/zlib1g-dev")
fi
if ((${#missing[@]})); then
	echo "FAIL: не хватает: ${missing[*]}; запустите с --install-deps"
	exit 1
fi

work="$(mktemp -d /tmp/wpp-verify-mtproxy.XXXXXX)"
pids=()
cleanup() {
	for pid in "${pids[@]}"; do
		pkill -TERM -P "$pid" >/dev/null 2>&1 || true
		kill -TERM "$pid" >/dev/null 2>&1 || true
	done
	sleep 1
	for pid in "${pids[@]}"; do
		pkill -KILL -P "$pid" >/dev/null 2>&1 || true
		kill -KILL "$pid" >/dev/null 2>&1 || true
	done
	rm -rf -- "$work"
}
trap cleanup EXIT
chmod 0755 "$work"

failures=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; failures=$((failures + 1)); }
info() { echo "INFO: $*"; }

for port in $(seq "$stats_port" $((stats_port + 2))) $(seq "$first_port" $((first_port + 47))); do
	if ss -Hltn "sport = :$port" | grep -q .; then
		echo "FAIL: порт $port занят"
		exit 1
	fi
done

info "скачивание и проверка архива MTProxy $mtproxy_commit"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
	--output "$work/MTProxy.tar.gz" \
	"https://github.com/TelegramMessenger/MTProxy/archive/${mtproxy_commit}.tar.gz"
if [[ "$(sha256sum "$work/MTProxy.tar.gz" | awk '{print $1}')" == "$mtproxy_checksum" ]]; then
	pass "SHA256 архива MTProxy совпадает с закреплённым"
else
	fail "SHA256 архива MTProxy не совпадает"
	exit 1
fi
mkdir "$work/src"
tar -C "$work/src" --strip-components=1 -xzf "$work/MTProxy.tar.gz"
chown -R nobody "$work/src"
info "сборка (1-3 минуты)"
if runuser -u nobody -- make -C "$work/src" -j"$(nproc)" >"$work/build.log" 2>&1 &&
	[[ -x "$work/src/objs/bin/mtproto-proxy" ]]; then
	pass "MTProxy собран"
else
	tail -n 30 "$work/build.log"
	fail "сборка MTProxy не удалась"
	exit 1
fi
binary="$work/src/objs/bin/mtproto-proxy"

curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
	--output "$work/proxy-secret" https://core.telegram.org/getProxySecret
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
	--output "$work/proxy-multi.conf" https://core.telegram.org/getProxyConfig
chmod 0644 "$work/proxy-secret" "$work/proxy-multi.conf"
if [[ "$(wc -c < "$work/proxy-secret")" -eq 128 ]] && grep -q '^proxy_for ' "$work/proxy-multi.conf"; then
	pass "proxy-secret и proxy-multi.conf скачаны"
else
	fail "proxy-secret или proxy-multi.conf некорректны"
fi

# Same NAT detection as upstream deploy/install.sh.
nat_args=()
local_address="$(ip -4 route get 149.154.175.50 2>/dev/null |
	sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]\+\).*/\1/p' | head -n 1)"
public_address="$(curl --fail --silent --ipv4 --max-time 15 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -n "$local_address" && -n "$public_address" && "$local_address" != "$public_address" ]]; then
	nat_args=(--nat-info "$local_address:$public_address")
	info "обнаружен NAT: $local_address -> $public_address"
else
	info "NAT не обнаружен (локальный $local_address, внешний ${public_address:-неизвестен})"
fi

random_secret() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }

# start_shard <name> <workers> <secret count> <first port> <stats port>; sets started_pid
started_pid=
start_shard() {
	local name="$1" workers="$2" count="$3" base="$4" stats="$5"
	local args=() ports=() i
	for ((i = 0; i < count; ++i)); do
		args+=(-S "$(random_secret)")
	done
	for ((i = 0; i < 16; ++i)); do
		ports+=("$((base + i))")
	done
	local joined
	joined="$(IFS=,; echo "${ports[*]}")"
	(
		ulimit -n 65536
		cd "$work"
		# -u names a user that does not exist: it must be ignored when not root.
		exec setpriv --reuid=nobody --regid=nogroup --clear-groups -- \
			"$binary" -u wpp-verify-no-such-user -p "$stats" --http-stats -H "$joined" \
			"${args[@]}" "${nat_args[@]}" --aes-pwd "$work/proxy-secret" "$work/proxy-multi.conf" \
			-M "$workers" -C 4096
	) >"$work/$name.log" 2>&1 &
	started_pid="$!"
	pids+=("$started_pid")
}

tree_rss_kib() {
	local pid="$1" total=0 child rss
	for child in "$pid" $(pgrep -P "$pid" || true); do
		rss="$(awk '/^VmRSS:/ {print $2}' "/proc/$child/status" 2>/dev/null || echo 0)"
		total=$((total + rss))
	done
	echo "$total"
}

listening_count() {
	local base="$1" i count=0
	for ((i = 0; i < 16; ++i)); do
		if ss -Hltn "sport = :$((base + i))" | grep -q .; then
			count=$((count + 1))
		fi
	done
	echo "$count"
}

# 17 secrets must abort on assert (ext_secret_cnt < 16).
start_shard s17 0 17 $((first_port + 32)) $((stats_port + 2))
pid17="$started_pid"
sleep 3
if kill -0 "$pid17" 2>/dev/null; then
	fail "процесс с 17 секретами не завершился"
else
	pass "17 секретов на процесс отклоняются (assert), предел — 16"
fi

start_shard m1 1 16 "$first_port" "$stats_port"
pid1="$started_pid"
start_shard m0 0 16 $((first_port + 16)) $((stats_port + 1))
pid0="$started_pid"
sleep 5
if kill -0 "$pid1" 2>/dev/null; then
	pass "шард -M 1 с 16 секретами запущен от nobody, -u с несуществующим пользователем проигнорирован"
else
	tail -n 20 "$work/m1.log"
	fail "шард -M 1 с 16 секретами не запустился"
fi
count="$(listening_count "$first_port")"
[[ "$count" -eq 16 ]] && pass "шард -M 1 слушает все 16 портов" || fail "шард -M 1 слушает $count из 16 портов"
if kill -0 "$pid0" 2>/dev/null; then
	count="$(listening_count $((first_port + 16)))"
	[[ "$count" -eq 16 ]] && pass "шард -M 0 (без воркеров) слушает все 16 портов" || fail "шард -M 0 слушает $count из 16 портов"
else
	info "шард -M 0 не запустился (см. журнал ниже); используем -M 1"
	tail -n 10 "$work/m0.log"
fi

stats="$(curl --silent --max-time 5 "http://127.0.0.1:$stats_port/stats" || true)"
if grep -q 'total_special_connections' <<<"$stats"; then
	pass "stats-порт отвечает на /stats с 127.0.0.1"
else
	fail "stats-порт не ответил на /stats"
fi
ss_line="$(ss -Hltn "sport = :$stats_port" | awk '{print $4}' | head -n 1)"
info "stats-порт слушает на: ${ss_line:-?} (внешний доступ закрывается nft)"
first_line="$(ss -Hltn "sport = :$first_port" | awk '{print $4}' | tr '\n' ' ')"
info "клиентский порт слушает на: ${first_line:-?}"

info "ожидание ${idle_seconds} с для замера RSS в простое"
sleep "$idle_seconds"
info "RSS шарда -M 1 (родитель + воркер): $(tree_rss_kib "$pid1") КиБ"
if kill -0 "$pid0" 2>/dev/null; then
	info "RSS шарда -M 0: $(tree_rss_kib "$pid0") КиБ"
fi
disconnects="$(grep -c 'Disconnected from RPC Middle-End' "$work/m1.log" || true)"
if [[ "$disconnects" -eq 0 ]]; then
	pass "нет 'Disconnected from RPC Middle-End' за ${idle_seconds} с"
else
	fail "'Disconnected from RPC Middle-End' встречается $disconnects раз (проблема NAT?)"
fi

if ((failures == 0)); then
	echo "ИТОГ: PASS"
else
	echo "ИТОГ: FAIL ($failures)"
	exit 1
fi

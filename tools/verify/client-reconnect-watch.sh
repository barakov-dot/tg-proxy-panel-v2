#!/usr/bin/env bash
# Manual check with a real Telegram client (FINDINGS.md, item 6).
# Samples relay /metrics while a client whose slot is blocked stays open and
# reports how fast it recreates streams and sessions.
# Needs a running relay; changes nothing.
# Usage: bash tools/verify/client-reconnect-watch.sh [seconds=120] [admin=127.0.0.1:8081] [max_streams_per_min=120]
set -euo pipefail

duration="${1:-120}"
admin="${2:-127.0.0.1:8081}"
threshold="${3:-120}"
interval=10

if ! command -v curl >/dev/null 2>&1; then
	echo "FAIL: нет curl"
	exit 1
fi

metric() {
	awk -v name="$1" '$1 == name {print $2}' <<<"$2"
}

sample() {
	curl --fail --silent --max-time 5 "http://$admin/metrics"
}

first="$(sample)" || {
	echo "FAIL: relay не отвечает на http://$admin/metrics"
	exit 1
}
echo "INFO: наблюдение ${duration} с; держите открытым клиент с заблокированным слотом"
previous="$first"
elapsed=0
while ((elapsed < duration)); do
	sleep "$interval"
	elapsed=$((elapsed + interval))
	current="$(sample)"
	printf 'INFO: t=%3ds  sessions_created +%s  streams_opened +%s  streams_rejected +%s  dial_failures +%s  sessions_live %s\n' \
		"$elapsed" \
		"$(($(metric tproxy_sessions_created_total "$current") - $(metric tproxy_sessions_created_total "$previous")))" \
		"$(($(metric tproxy_streams_opened_total "$current") - $(metric tproxy_streams_opened_total "$previous")))" \
		"$(($(metric tproxy_streams_rejected_total "$current") - $(metric tproxy_streams_rejected_total "$previous")))" \
		"$(($(metric tproxy_backend_dial_failures_total "$current") - $(metric tproxy_backend_dial_failures_total "$previous")))" \
		"$(metric tproxy_sessions_live "$current")"
	previous="$current"
done

opened=$(($(metric tproxy_streams_opened_total "$previous") - $(metric tproxy_streams_opened_total "$first")))
created=$(($(metric tproxy_sessions_created_total "$previous") - $(metric tproxy_sessions_created_total "$first")))
per_minute=$((opened * 60 / duration))
sessions_per_minute=$((created * 60 / duration))
echo "INFO: итого потоков в минуту: $per_minute, новых сессий в минуту: $sessions_per_minute"
echo "INFO: метрики глобальные: во время замера другие клиенты должны быть отключены"
if ((per_minute <= threshold)); then
	echo "ИТОГ: PASS (потоков в минуту $per_minute <= $threshold)"
else
	echo "ИТОГ: FAIL (потоков в минуту $per_minute > $threshold)"
	exit 1
fi

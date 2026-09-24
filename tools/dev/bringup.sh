#!/usr/bin/env bash
# M1 test stand: minimal installation of the core on a clean VPS.
# NOT the production installer (that is install.sh, stage M5): no questions,
# no host firewall, no panel/bot. Idempotent: rerun keeps data and binaries.
#
# Usage (as root, repository cloned to /opt/webproxy/src):
#   bash /opt/webproxy/src/tools/dev/bringup.sh --domain proxy.example.com --email you@example.com \
#        [--base-path SLUG|none] [--users 300]
set -euo pipefail
umask 022

caddy_version=2.11.4
caddy_checksum=8220d1f013b6f27510247b2360c9e0ca9f018feebd82515f07635318b34ff9777ccc8fd0b6e6f2486ce3a33fe389fbb7db12d05baa474f4587509fb4f5ebf1c9
go_version=1.26.5
go_checksum=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
relay_commit=acc252ece3a25c29e9b83f608499a5567a33ab2a
relay_checksum=4db6003ac7f06aa8b1e179249b470c4b0d8db3a62cf5152d1cabc86bf3c7197b
mtproxy_commit=f36d8af769ffaeac36978d38c2c0f6d1104c2137
mtproxy_checksum=919795c416b870670841a21d1930ad97a24c7b84b9eb8c6f9e3de32f2fdf4655

src=/opt/webproxy/src
bin=/opt/webproxy/bin
etc=/etc/webproxy
lib=/var/lib/webproxy

domain=
email=
base_path=
users=300
while [[ $# -gt 0 ]]; do
	case "$1" in
		--domain) domain="${2:-}"; shift 2 ;;
		--email) email="${2:-}"; shift 2 ;;
		--base-path) base_path="${2:-}"; shift 2 ;;
		--users) users="${2:-}"; shift 2 ;;
		*) echo "Неизвестный параметр: $1" >&2; exit 2 ;;
	esac
done

die() { echo "Ошибка: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

[[ "${EUID}" -eq 0 ]] || die "запустите от root"
[[ "$(uname -m)" == "x86_64" ]] || die "нужен x86_64"
[[ -d /run/systemd/system ]] || die "нужен systemd"
[[ -f "$src/webproxy/cli.py" ]] || die "репозиторий должен быть в $src"
[[ "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ && "$domain" == *.* ]] || die "--domain: домен в нижнем регистре (ASCII)"
[[ "$email" =~ ^[A-Za-z0-9._+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] || die "--email: адрес для ACME"
[[ "$users" =~ ^[1-9][0-9]*$ ]] || die "--users: целое число"
if [[ -f "$etc/config.json" ]]; then
	echo "Конфигурация уже есть — домен и base_path берутся из $etc/config.json"
elif [[ "$base_path" == "none" ]]; then
	base_path=
elif [[ -z "$base_path" ]]; then
	base_path="$(head -c 10 /dev/urandom | base32 | tr 'A-Z' 'a-z')"
fi

download() { # url output sha-command checksum
	curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --output "$2" "$1"
	[[ "$("$3" "$2" | awk '{print $1}')" == "$4" ]] || die "контрольная сумма не совпала: $1"
}

step "Пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends ca-certificates curl git nftables qrencode \
	build-essential libssl-dev zlib1g-dev sqlite3 iproute2 python3 sudo

step "Пользователь и каталоги"
id webproxy >/dev/null 2>&1 || useradd --system --home "$lib" --shell /usr/sbin/nologin webproxy
install -d -o root -g root -m 0755 /opt/webproxy "$bin"
install -d -o webproxy -g webproxy -m 0700 "$etc" "$etc/shards"
install -d -o webproxy -g webproxy -m 0750 "$lib"
install -d -o webproxy -g webproxy -m 0700 "$lib/caddy" "$lib/backups" "$lib/mtproxy"
install -d -o webproxy -g webproxy -m 0755 "$lib/site"

work="$(mktemp -d /tmp/wpp-bringup.XXXXXX)"
chmod 0755 "$work"
trap 'chmod -R u+w "$work" 2>/dev/null || true; rm -rf -- "$work"' EXIT

step "Caddy $caddy_version"
if [[ ! -x "$bin/caddy" ]] || ! "$bin/caddy" version | grep -q "v$caddy_version"; then
	download "https://github.com/caddyserver/caddy/releases/download/v${caddy_version}/caddy_${caddy_version}_linux_amd64.tar.gz" \
		"$work/caddy.tar.gz" sha512sum "$caddy_checksum"
	tar -C "$work" -xzf "$work/caddy.tar.gz" caddy
	install -o root -g root -m 0755 "$work/caddy" "$bin/caddy"
fi

step "Relay (tproxy-server $relay_commit)"
if [[ "$(cat "$bin/.relay-commit" 2>/dev/null)" != "$relay_commit" ]]; then
	go_binary=
	for candidate in "$(command -v go 2>/dev/null || true)" /opt/go*/bin/go; do
		if [[ -n "$candidate" && -x "$candidate" ]]; then
			version="$("$candidate" env GOVERSION 2>/dev/null || true)"
			if [[ "$version" =~ ^go1\.([0-9]+) ]] && ((BASH_REMATCH[1] >= 20)); then
				go_binary="$candidate"
				break
			fi
		fi
	done
	if [[ -z "$go_binary" ]]; then
		download "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz" "$work/go.tar.gz" sha256sum "$go_checksum"
		tar -C "$work" -xzf "$work/go.tar.gz"
		mv "$work/go" "/opt/go${go_version}"
		go_binary="/opt/go${go_version}/bin/go"
	fi
	download "https://github.com/telegramdesktop/tproxy-server/archive/${relay_commit}.tar.gz" \
		"$work/relay.tar.gz" sha256sum "$relay_checksum"
	mkdir "$work/relay"
	tar -C "$work/relay" --strip-components=1 -xzf "$work/relay.tar.gz"
	(
		cd "$work/relay"
		export GOPATH="$work/gopath" GOCACHE="$work/gocache" GOFLAGS=-modcacherw
		"$go_binary" test ./...
		"$go_binary" build -trimpath -ldflags='-s -w' -o "$work/tproxy-server" ./cmd/tproxy-server
	)
	install -o root -g root -m 0755 "$work/tproxy-server" "$bin/tproxy-server"
	echo "$relay_commit" > "$bin/.relay-commit"
fi

step "MTProxy $mtproxy_commit"
if [[ "$(cat "$bin/.mtproxy-commit" 2>/dev/null)" != "$mtproxy_commit" ]]; then
	download "https://github.com/TelegramMessenger/MTProxy/archive/${mtproxy_commit}.tar.gz" \
		"$work/mtproxy.tar.gz" sha256sum "$mtproxy_checksum"
	mkdir "$work/mtproxy"
	tar -C "$work/mtproxy" --strip-components=1 -xzf "$work/mtproxy.tar.gz"
	chown -R nobody "$work/mtproxy"
	runuser -u nobody -- make -C "$work/mtproxy" -j"$(nproc)" >"$work/mtproxy-build.log" 2>&1 ||
		{ tail -n 30 "$work/mtproxy-build.log"; die "сборка MTProxy"; }
	install -o root -g root -m 0755 "$work/mtproxy/objs/bin/mtproto-proxy" "$bin/mtproto-proxy"
	echo "$mtproxy_commit" > "$bin/.mtproxy-commit"
fi

step "Конфигурация Telegram для MTProxy"
for pair in "getProxySecret:proxy-secret" "getProxyConfig:proxy-multi.conf"; do
	curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
		--output "$work/${pair#*:}" "https://core.telegram.org/${pair%%:*}"
done
[[ "$(wc -c < "$work/proxy-secret")" -eq 128 ]] || die "proxy-secret"
grep -q '^proxy_for ' "$work/proxy-multi.conf" || die "proxy-multi.conf"
install -o webproxy -g webproxy -m 0600 "$work/proxy-secret" "$lib/mtproxy/proxy-secret"
install -o webproxy -g webproxy -m 0600 "$work/proxy-multi.conf" "$lib/mtproxy/proxy-multi.conf"

step "token.key и сайт-заглушка"
if [[ ! -e "$etc/token.key" ]]; then
	head -c 32 /dev/urandom > "$work/token.key"
	install -o webproxy -g webproxy -m 0600 "$work/token.key" "$etc/token.key"
fi
if [[ ! -e "$lib/site/index.html" ]]; then
	# Test stand only: M5 generates a unique site per installation.
	printf '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Заметки</title><h1>Заметки</h1><p>Скоро здесь будет сайт.</p></html>\n' \
		> "$lib/site/index.html"
	printf '<!doctype html><html lang="ru"><meta charset="utf-8"><title>Не найдено</title><h1>404</h1></html>\n' \
		> "$lib/site/404.html"
	chown webproxy:webproxy "$lib/site/index.html" "$lib/site/404.html"
fi

step "NAT"
nat_info=
local_address="$(ip -4 route get 149.154.175.50 2>/dev/null | sed -n 's/.*[[:space:]]src[[:space:]]\+\([0-9.]\+\).*/\1/p' | head -n 1)"
public_address="$(curl --fail --silent --ipv4 --max-time 15 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -n "$local_address" && -n "$public_address" && "$local_address" != "$public_address" ]]; then
	nat_info="$local_address:$public_address"
	echo "NAT: $nat_info"
else
	echo "NAT не обнаружен"
fi

step "wppctl, sudoers, юниты"
install -o root -g root -m 0755 "$src/webproxy/ctl.py" /usr/local/sbin/wppctl
install -o root -g root -m 0440 "$src/deploy/sudoers-webproxy" "$work/sudoers"
visudo -cf "$work/sudoers" >/dev/null || die "sudoers"
install -o root -g root -m 0440 "$work/sudoers" /etc/sudoers.d/webproxy
for unit in wpp-mtproxy@.service wpp-relay.service wpp-firewall.service wpp-caddy.service; do
	install -o root -g root -m 0644 "$src/systemd/$unit" "/etc/systemd/system/$unit"
done
systemctl daemon-reload
systemctl enable --now wpp-firewall.service

step "Инициализация пула"
cd "$src"
runuser -u webproxy -- env PYTHONDONTWRITEBYTECODE=1 python3 -m webproxy.cli init \
	--domain "$domain" --base-path "$base_path" --nat-info "$nat_info" --users "$users"
systemctl enable wpp-relay.service

step "Caddy"
panel_path="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["panel_path"])' "$etc/config.json")"
domain="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["domain"])' "$etc/config.json")"
install -o webproxy -g webproxy -m 0600 "$src/deploy/Caddyfile" "$etc/Caddyfile"
printf 'WPP_DOMAIN=%s\nWPP_PANEL_PATH=%s\nACME_EMAIL=%s\n' "$domain" "$panel_path" "$email" > "$work/caddy.env"
install -o webproxy -g webproxy -m 0600 "$work/caddy.env" "$etc/caddy.env"
WPP_DOMAIN="$domain" WPP_PANEL_PATH="$panel_path" ACME_EMAIL="$email" \
	"$bin/caddy" validate --config "$etc/Caddyfile" --adapter caddyfile >/dev/null
systemctl enable wpp-caddy.service
systemctl restart wpp-caddy.service

step "Проверка"
for _ in $(seq 1 30); do
	curl --fail --silent --output /dev/null http://127.0.0.1:8081/healthz && break
	sleep 1
done
curl --fail --silent --output /dev/null http://127.0.0.1:8081/healthz || die "relay не отвечает на /healthz"
runuser -u webproxy -- env PYTHONDONTWRITEBYTECODE=1 python3 -m webproxy.cli status
echo
echo "Готово. Дальше: docs/TESTING.md, раздел M1."

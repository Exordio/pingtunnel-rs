#!/usr/bin/env bash
# Сквозной (end-to-end) тест туннеля. Требует прав на RAW-сокеты для сервера
# (запускайте через sudo, либо выдайте бинарю CAP_NET_RAW — см. README).
#
# Поднимает локальный HTTP-сервер, сервер и клиент pingtunnel, затем тянет
# страницу через TCP-туннель и сравнивает результат. Логи компонентов пишутся
# в /tmp/pt_server.log и /tmp/pt_client.log.
set -uo pipefail

BIN="${BIN:-./target/release/pingtunnel}"
KEY="${KEY:-123456}"
HTTP_PORT=18080
LOCAL_PORT=14455
LOGLEVEL="${LOGLEVEL:-info}"

cleanup() {
  kill "${HTTP_PID:-}" "${SRV_PID:-}" "${CLI_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT

echo ">> запускаем локальный HTTP-сервер на :$HTTP_PORT"
python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

echo ">> запускаем pingtunnel server (лог: /tmp/pt_server.log)"
RUST_LOG="$LOGLEVEL" "$BIN" --type server --key "$KEY" --loglevel "$LOGLEVEL" \
  >/tmp/pt_server.log 2>&1 &
SRV_PID=$!
sleep 1

echo ">> запускаем pingtunnel client TCP forward :$LOCAL_PORT -> 127.0.0.1:$HTTP_PORT (лог: /tmp/pt_client.log)"
RUST_LOG="$LOGLEVEL" "$BIN" --type client -l "127.0.0.1:$LOCAL_PORT" -s 127.0.0.1 \
  -t "127.0.0.1:$HTTP_PORT" --tcp 1 --key "$KEY" --loglevel "$LOGLEVEL" \
  >/tmp/pt_client.log 2>&1 &
CLI_PID=$!
sleep 2

echo ">> запрос через туннель (curl, max 20s)"
if curl -fsS --max-time 20 "http://127.0.0.1:$LOCAL_PORT/" >/tmp/pt_tunnel.html; then
  echo ">> OK: получено $(wc -c </tmp/pt_tunnel.html) байт через ICMP-туннель"
  exit 0
else
  echo ">> ОШИБКА: запрос через туннель не удался"
  echo "---- последние строки /tmp/pt_server.log ----"; tail -n 15 /tmp/pt_server.log
  echo "---- последние строки /tmp/pt_client.log ----"; tail -n 15 /tmp/pt_client.log
  exit 1
fi

#!/usr/bin/env bash
# Нагрузочный тест: много параллельных соединений через SOCKS5-туннель.
# Требует CAP_NET_RAW на бинаре (sudo setcap cap_net_raw+ep ./target/release/pingtunnel)
# или запуска под root.
#
# Поднимает HTTP-сервер с крупным файлом, сервер+клиент pingtunnel (socks5),
# затем запускает N параллельных загрузок через прокси и следит за CPU/успехом.
set -uo pipefail

BIN="${BIN:-./target/release/pingtunnel}"
KEY="${KEY:-123456}"
HTTP_PORT=18080
SOCKS_PORT=11080
N="${N:-40}"          # число параллельных соединений
SIZE_MB="${SIZE_MB:-2}"
LOGLEVEL="${LOGLEVEL:-info}"
WWW="$(mktemp -d)"

cleanup() {
  kill "${HTTP_PID:-}" "${SRV_PID:-}" "${CLI_PID:-}" 2>/dev/null || true
  rm -rf "$WWW"
}
trap cleanup EXIT

head -c $((SIZE_MB*1024*1024)) /dev/urandom >"$WWW/blob.bin"

echo ">> HTTP :$HTTP_PORT (файл ${SIZE_MB}MB)"
( cd "$WWW" && python3 -m http.server "$HTTP_PORT" >/dev/null 2>&1 ) &
HTTP_PID=$!
sleep 1

echo ">> server (лог /tmp/pt_server.log)"
RUST_LOG="$LOGLEVEL" "$BIN" --type server --key "$KEY" --loglevel "$LOGLEVEL" >/tmp/pt_server.log 2>&1 &
SRV_PID=$!
sleep 1

echo ">> client socks5 :$SOCKS_PORT (лог /tmp/pt_client.log)"
RUST_LOG="$LOGLEVEL" "$BIN" --type client -l "127.0.0.1:$SOCKS_PORT" -s 127.0.0.1 \
  --sock5 1 --key "$KEY" --loglevel "$LOGLEVEL" >/tmp/pt_client.log 2>&1 &
CLI_PID=$!
sleep 2

echo ">> $N параллельных загрузок ${SIZE_MB}MB через socks5..."
RES="$(mktemp)"
for i in $(seq 1 "$N"); do
  ( if curl -s -o /dev/null --socks5-hostname "127.0.0.1:$SOCKS_PORT" --max-time 60 \
        "http://127.0.0.1:$HTTP_PORT/blob.bin"; then echo ok; else echo fail; fi >>"$RES" ) &
done

# Мониторинг CPU клиента и сервера во время загрузок
for s in 1 2 3 4 5 6 7 8; do
  sleep 2
  scpu=$(ps -o %cpu= -p "$SRV_PID" 2>/dev/null | tr -d ' ')
  ccpu=$(ps -o %cpu= -p "$CLI_PID" 2>/dev/null | tr -d ' ')
  echo "   t=$((s*2))s  server_cpu=${scpu:-?}%  client_cpu=${ccpu:-?}%"
done

wait
ok=$(grep -c '^ok' "$RES" 2>/dev/null || echo 0)
fail=$(grep -c '^fail' "$RES" 2>/dev/null || echo 0)
rm -f "$RES"
echo ">> РЕЗУЛЬТАТ: ok=$ok fail=$fail из $N"
echo ">> Хвост статистики сервера:"; grep 'Packet/s' /tmp/pt_server.log | tail -3
echo ">> Хвост статистики клиента:"; grep 'Packet/s' /tmp/pt_client.log | tail -3

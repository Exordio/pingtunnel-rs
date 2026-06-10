# Лёгкий контейнер для бенчмаркинга/профилирования клиента protofuse.
# Внутри root → можно ставить профайлеры и держать CAP_NET_RAW/SYS_PTRACE.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb strace curl procps ca-certificates iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work
CMD ["sleep", "infinity"]

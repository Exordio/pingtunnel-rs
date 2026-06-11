//! protofuse — туннелирование TCP/UDP/SOCKS5 поверх ICMP и произвольных
//! IP-протоколов, с обфускацией трафика (async, tokio). Идейный прародитель -
//! https://github.com/esrrhs/pingtunnel.

mod client;
mod crypto;
mod forward;
mod framemgr;
mod icmp;
mod proto;
mod ring;
mod server;
mod socks5;
mod stats;
mod tui;
mod udprel;
mod util;

use clap::Parser;
use crypto::{Crypto, EncryptionMode};
use stats::Stats;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Parser, Debug)]
#[command(
    name = "protofuse",
    about = "Туннелирование TCP/UDP/SOCKS5 поверх ICMP и произвольных IP-протоколов с обфускацией (async)",
    long_about = None
)]
struct Args {
    /// Режим: client или server
    #[arg(long = "type", value_name = "TYPE")]
    r#type: String,
    #[arg(short = 'l', long = "l", default_value = "")]
    listen: String,
    #[arg(short = 't', long = "t", default_value = "")]
    target: String,
    #[arg(short = 's', long = "s", default_value = "")]
    server: String,
    #[arg(long = "icmp_l", default_value = "0.0.0.0")]
    icmp_listen: String,
    #[arg(long = "timeout", default_value_t = 60)]
    timeout: i32,
    #[arg(long = "key", default_value_t = 0)]
    key: i32,
    #[arg(long = "encrypt", default_value = "")]
    encrypt: String,
    #[arg(long = "encrypt-key", default_value = "")]
    encrypt_key: String,
    #[arg(long = "tcp", default_value_t = 0)]
    tcp: i32,
    /// Надёжный UDP: датаграммы идут через FrameMgr (ретрансмиссия + порядок),
    /// как у TCP. Иначе UDP шлётся без подтверждений и теряется при потерях в
    /// ICMP-канале. 1 = включить. Работает для UDP-проброса (-t) и SOCKS5 UDP
    /// ASSOCIATE (-sock5 1); в чистом TCP-форварде смысла не имеет.
    #[arg(long = "udp_rel", default_value_t = 0)]
    udp_rel: i32,
    /// Размер буфера TCP (на соединение, в каждую сторону)
    #[arg(long = "tcp_bs", default_value_t = 256 * 1024)]
    tcp_bs: i32,
    /// Максимальное окно (число фреймов в полёте)
    #[arg(long = "tcp_mw", default_value_t = 2048)]
    tcp_mw: i32,
    #[arg(long = "tcp_rst", default_value_t = 400)]
    tcp_rst: i32,
    #[arg(long = "tcp_gz", default_value_t = 0)]
    tcp_gz: i32,
    /// Размер кадра в байтах (0 = по умолчанию 888, маскировка под ping).
    /// Крупнее = меньше пакетов/syscalls/CPU, но теряется маскировка и идёт
    /// IP-фрагментация выше MTU. Ставится независимо на клиенте и сервере, напр. 8000.
    #[arg(long = "jumbo", default_value_t = 0)]
    jumbo: usize,
    #[arg(long = "loglevel", default_value = "info")]
    loglevel: String,
    #[arg(long = "noprint", default_value_t = 0)]
    noprint: i32,
    #[arg(long = "sock5", default_value_t = 0)]
    sock5: i32,
    #[arg(long = "s5user", default_value = "")]
    s5user: String,
    #[arg(long = "s5pass", default_value = "")]
    s5pass: String,
    #[arg(long = "maxconn", default_value_t = 0)]
    maxconn: i32,
    #[arg(long = "conntt", default_value_t = 1000)]
    conntt: i32,
    #[arg(long = "forward", default_value = "")]
    forward: String,
    /// Номер IP-протокола транспорта. 1 = ICMP (по умолчанию). Любой другой
    /// (напр. 253/254 - зарезервированы RFC 3692 под эксперименты) гонит трафик
    /// поверх кастомного IP-протокола вместо ICMP. Нужен RAW-сокет (root/CAP_NET_RAW)
    /// на обоих концах, datagram-фоллбэка нет. ВНИМАНИЕ: не переживает NAT и
    /// режется большинством файрволов - работает лишь при прямой маршрутизации
    /// без NAT по пути. Значение должно совпадать на клиенте и сервере.
    #[arg(long = "ip_proto", default_value_t = 1)]
    ip_proto: u8,
    /// Экспериментальная ротация IP-протокола: диапазон `LO-HI` (напр. `100-254`,
    /// допустимо 1..=254). Если задан, клиент выбирает случайный IP-протокол на
    /// каждое соединение, приём идёт через один AF_PACKET-сокет с BPF-фильтром по
    /// диапазону (сервер отвечает тем же протоколом). Перекрывает `--ip_proto`.
    /// Диапазон должен совпадать на клиенте и сервере; нужен root/CAP_NET_RAW на
    /// обоих концах. ВНИМАНИЕ: кастомные протоколы не переживают NAT и заметны для
    /// сетевых классификаторов. Пусто = выключено.
    #[arg(long = "ip_proto_range", default_value = "")]
    ip_proto_range: String,
    /// Dynamic Packet Padding: к каждому пакету дописывается 0..=N случайных байт
    /// (внутри шифрования), рандомизируя итоговый размер пакета по длинам.
    /// Получатель паддинг игнорирует, согласование сторон не нужно.
    /// 0 = выключено. Разумные значения - 64..256.
    #[arg(long = "pad", default_value_t = 0)]
    pad: u16,
    /// Header Obfuscation: внутренний заголовок (id сессии, флаги) шифруется
    /// целиком вместе с данными, а с провода снимается псевдо-echo обёртка - на
    /// проводе остаётся лишь 12-байтный nonce и шифртекст, т.е. сплошной шум.
    /// Требует включённого шифрования (--encrypt) и кастомного IP-протокола
    /// (--ip_proto/--ip_proto_range): ICMP без echo-заголовка невалиден. Должно
    /// совпадать на клиенте и сервере.
    #[arg(long = "obfs", default_value_t = false)]
    obfs: bool,
    /// Базовый интервал фонового keep-alive (ping для удержания NAT/сессии), сек.
    #[arg(long = "keepalive", default_value_t = 1)]
    keepalive: u64,
    /// Джиттер keep-alive: случайный разброс +/- N секунд вокруг базового
    /// интервала (--keepalive), чтобы фоновые пакеты не шли строго периодичным
    /// «пульсом». 0 = строго по интервалу. Только клиент.
    #[arg(long = "keepalive_jitter", default_value_t = 0)]
    keepalive_jitter: u64,
    /// Периодический возврат свободной памяти ОС через malloc_trim каждые N сек:
    /// glibc держит освобождённую закрытыми соединениями память в аренах и не
    /// отдаёт её ядру сам, поэтому RSS застывает на пиковом значении. Возврат
    /// затрагивает только уже свободные страницы и не влияет на соединения.
    /// 0 = выключено (по умолчанию). Эффективно лишь на glibc-сборках.
    #[arg(long = "mem_trim", default_value_t = 0)]
    mem_trim: u64,
    /// Интерактивный TUI: графики скорости TX/RX и список активных соединений
    /// (тип, цель, IP-протокол транспорта, объём трафика). Туннель при этом
    /// работает в обычном режиме; логирование в stdout отключается, чтобы не
    /// портить интерфейс. Выход - q/Esc/Ctrl-C.
    #[arg(long = "interactive", default_value_t = false)]
    interactive: bool,
}

/// Краткое описание набора IP-протоколов транспорта для заголовка TUI.
fn protos_desc(protos: &[u8]) -> String {
    match protos {
        [] => "ICMP".to_string(),
        [p] => stats::proto_name(*p),
        _ => {
            let lo = protos.iter().min().copied().unwrap_or(1);
            let hi = protos.iter().max().copied().unwrap_or(1);
            format!("ротация [{lo}..{hi}]")
        }
    }
}

/// Строит список IP-протоколов транспорта: либо диапазон `--ip_proto_range`
/// (приоритет), либо одиночный `--ip_proto`.
fn build_ip_protos(single: u8, range: &str) -> anyhow::Result<Vec<u8>> {
    let range = range.trim();
    if range.is_empty() {
        return Ok(vec![single.max(1)]);
    }
    let (lo, hi) = range
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("--ip_proto_range: ожидался формат LO-HI, напр. 100-254"))?;
    let lo: u16 = lo
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("--ip_proto_range: неверный LO"))?;
    let hi: u16 = hi
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("--ip_proto_range: неверный HI"))?;
    // 255 (IPPROTO_RAW) только на отправку, принимать нельзя; 0 невалиден.
    if lo < 1 || hi > 254 || lo > hi {
        anyhow::bail!("--ip_proto_range: допустимо 1..=254 и LO<=HI");
    }
    Ok((lo..=hi).map(|p| p as u8).collect())
}

/// Проверяет применимость `--obfs`: нужно шифрование (иначе заголовок не скрыть)
/// и кастомный IP-протокол (ICMP без echo-обёртки невалиден, маскировка теряется).
fn validate_obfs(obfs: bool, has_crypto: bool, ip_protos: &[u8]) -> anyhow::Result<()> {
    if !obfs {
        return Ok(());
    }
    if !has_crypto {
        anyhow::bail!("--obfs требует включённого шифрования (--encrypt + --encrypt-key)");
    }
    if ip_protos == [icmp::IP_PROTO_ICMP] {
        anyhow::bail!(
            "--obfs неприменим к ICMP: нужен кастомный IP-протокол (--ip_proto N или --ip_proto_range)"
        );
    }
    Ok(())
}

fn normalize_args() -> Vec<String> {
    std::env::args()
        .enumerate()
        .map(|(i, a)| {
            if i == 0 || a.starts_with("--") {
                return a;
            }
            if let Some(rest) = a.strip_prefix('-') {
                if rest.len() > 1 && rest.starts_with(|c: char| c.is_ascii_alphabetic()) {
                    return format!("--{rest}");
                }
            }
            a
        })
        .collect()
}

fn main() {
    let args = Args::parse_from(normalize_args());

    // В TUI логи в stdout/stderr изуродовали бы интерфейс - глушим их.
    let level = if args.interactive || args.noprint > 0 {
        "off"
    } else {
        match args.loglevel.as_str() {
            "debug" => "debug",
            "warn" => "warn",
            "error" => "error",
            _ => "info",
        }
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(level)).init();

    if args.r#type != "client" && args.r#type != "server" {
        eprintln!("error: -type must be 'client' or 'server'");
        std::process::exit(1);
    }

    let mode = match EncryptionMode::parse(&args.encrypt) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Invalid encryption mode: {e}");
            std::process::exit(1);
        }
    };
    if mode != EncryptionMode::None && args.encrypt_key.is_empty() {
        eprintln!("Encryption key is required when encryption mode is specified");
        std::process::exit(1);
    }
    let crypto: Option<Crypto> = match Crypto::new(mode, &args.encrypt_key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to create crypto config: {e}");
            std::process::exit(1);
        }
    };

    log::info!("start... key {}", args.key);

    let stats = Arc::new(Stats::default());

    let workers = num_cpus::get().max(1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    if args.interactive {
        run_interactive(rt, args, crypto, stats);
        return;
    }

    let result = rt.block_on(async move {
        if args.r#type == "server" {
            run_server(args, crypto, stats).await
        } else {
            run_client(args, crypto, stats).await
        }
    });

    if let Err(e) = result {
        log::error!("ERROR: {e}");
        std::process::exit(1);
    }
}

/// Интерактивный режим: туннель крутится фоновой задачей на runtime, а TUI
/// блокирует главный поток. Когда туннель завершается (обычно лишь при ошибке),
/// взводится флаг, по которому TUI выходит и восстанавливает терминал.
fn run_interactive(
    rt: tokio::runtime::Runtime,
    args: Args,
    crypto: Option<Crypto>,
    stats: Arc<Stats>,
) {
    let is_server = args.r#type == "server";
    let protos = build_ip_protos(args.ip_proto, &args.ip_proto_range).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });
    let meta = tui::Meta {
        mode: args.r#type.clone(),
        listen: if is_server { args.icmp_listen.clone() } else { args.listen.clone() },
        server: if is_server { String::new() } else { args.server.clone() },
        protos: protos_desc(&protos),
    };

    let done = Arc::new(AtomicBool::new(false));
    let err_slot: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));

    let done_bg = done.clone();
    let err_bg = err_slot.clone();
    let stats_bg = stats.clone();
    rt.spawn(async move {
        let r = if is_server {
            run_server(args, crypto, stats_bg).await
        } else {
            run_client(args, crypto, stats_bg).await
        };
        if let Err(e) = r {
            *err_bg.lock().unwrap() = Some(format!("{e}"));
        }
        done_bg.store(true, Ordering::SeqCst);
    });

    let res = tui::run(stats, meta, done);
    // Терминал восстановлен (TermGuard в tui::run). Теперь можно печатать ошибки.
    if let Err(e) = res {
        eprintln!("tui error: {e}");
    }
    if let Some(e) = err_slot.lock().unwrap().take() {
        eprintln!("ERROR: {e}");
        std::process::exit(1);
    }
}

fn frame_size(jumbo: usize) -> usize {
    if jumbo > 0 {
        jumbo.clamp(256, 60000)
    } else {
        proto::FRAME_MAX_SIZE
    }
}

async fn run_server(args: Args, crypto: Option<Crypto>, stats: Arc<Stats>) -> anyhow::Result<()> {
    let forward = forward::parse_forward_url(&args.forward)?;
    if forward.is_some() {
        log::info!("Forward proxy configured: {}", args.forward);
    }
    let ip_protos = build_ip_protos(args.ip_proto, &args.ip_proto_range)?;
    validate_obfs(args.obfs, crypto.is_some(), &ip_protos)?;
    let cfg = server::ServerConfig {
        icmp_listen: args.icmp_listen.clone(),
        key: args.key,
        maxconn: args.maxconn,
        connect_timeout: args.conntt,
        frame_size: frame_size(args.jumbo),
        ip_protos,
        pad_max: args.pad,
        obfs: args.obfs,
        mem_trim_secs: args.mem_trim,
    };
    let srv = server::Server::new(cfg, crypto, forward, stats)?;
    srv.run().await
}

async fn run_client(args: Args, crypto: Option<Crypto>, stats: Arc<Stats>) -> anyhow::Result<()> {
    if args.listen.is_empty() || args.server.is_empty() {
        anyhow::bail!("client requires -l and -s");
    }
    let mut tcp = args.tcp;
    if args.sock5 != 0 {
        tcp = 1;
    }
    // tcp==0 без sock5 = режим чистого UDP-проброса (нужен -t).
    if args.sock5 == 0 && args.target.is_empty() {
        anyhow::bail!("client requires -t (target) for UDP/TCP forward, or -sock5 1");
    }
    // Надёжный UDP применим к UDP-путям: чистому UDP-пробросу и SOCKS5 UDP
    // ASSOCIATE. В чистом TCP-форварде (-tcp 1 без -sock5) UDP нет — там флаг
    // не имеет смысла. На TCP-часть SOCKS5 (CONNECT) флаг не влияет.
    let plain_udp = tcp == 0 && args.sock5 == 0;
    let udp_reliable = args.udp_rel != 0 && (plain_udp || args.sock5 != 0);
    if args.udp_rel != 0 && !udp_reliable {
        log::warn!("--udp_rel игнорируется: в чистом TCP-форварде UDP нет (нужен UDP-проброс или -sock5)");
    }
    if args.tcp_mw * 10 > proto::FRAME_MAX_ID {
        anyhow::bail!("tcp win too big, max = {}", proto::FRAME_MAX_ID / 10);
    }
    let ip_protos = build_ip_protos(args.ip_proto, &args.ip_proto_range)?;
    validate_obfs(args.obfs, crypto.is_some(), &ip_protos)?;

    let cfg = client::ClientConfig {
        listen: args.listen.clone(),
        server: args.server.clone(),
        target: args.target.clone(),
        timeout: args.timeout,
        key: args.key,
        icmp_listen: args.icmp_listen.clone(),
        tcpmode: tcp,
        buffersize: args.tcp_bs,
        maxwin: args.tcp_mw,
        resend: args.tcp_rst,
        compress: args.tcp_gz,
        frame_size: frame_size(args.jumbo),
        sock5: args.sock5,
        s5user: args.s5user.clone(),
        s5pass: args.s5pass.clone(),
        udp_reliable,
        ip_protos,
        pad_max: args.pad,
        obfs: args.obfs,
        keepalive_secs: args.keepalive,
        keepalive_jitter: args.keepalive_jitter,
        mem_trim_secs: args.mem_trim,
    };
    let cli = client::Client::new(cfg, crypto, stats)?;
    cli.run().await
}

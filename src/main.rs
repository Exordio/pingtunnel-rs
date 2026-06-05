//! pingtunnel — туннелирование TCP/UDP/SOCKS5 поверх ICMP.
//! Rust-порт https://github.com/esrrhs/pingtunnel.

mod client;
mod crypto;
mod forward;
mod framemgr;
mod icmp;
mod proto;
mod ring;
mod server;
mod socks5;
mod util;

use clap::Parser;
use crypto::{Crypto, EncryptionMode};

#[derive(Parser, Debug)]
#[command(
    name = "pingtunnel",
    about = "Туннелирование TCP/UDP/SOCKS5 трафика поверх ICMP (порт esrrhs/pingtunnel)",
    long_about = None
)]
struct Args {
    /// Режим: client или server
    #[arg(long = "type", value_name = "TYPE")]
    r#type: String,

    /// Локальный адрес прослушивания (клиент)
    #[arg(short = 'l', long = "l", default_value = "")]
    listen: String,

    /// Адрес целевого назначения (клиент)
    #[arg(short = 't', long = "t", default_value = "")]
    target: String,

    /// Адрес сервера (клиент)
    #[arg(short = 's', long = "s", default_value = "")]
    server: String,

    /// Адрес прослушивания ICMP-трафика
    #[arg(long = "icmp_l", default_value = "0.0.0.0")]
    icmp_listen: String,

    /// Таймаут соединения, сек
    #[arg(long = "timeout", default_value_t = 60)]
    timeout: i32,

    /// Числовой ключ-пароль (0..2147483647)
    #[arg(long = "key", default_value_t = 0)]
    key: i32,

    /// Режим шифрования: aes128, aes256, chacha20
    #[arg(long = "encrypt", default_value = "")]
    encrypt: String,

    /// Ключ шифрования (base64 или парольная фраза)
    #[arg(long = "encrypt-key", default_value = "")]
    encrypt_key: String,

    /// Включить режим TCP
    #[arg(long = "tcp", default_value_t = 0)]
    tcp: i32,

    /// Размер буфера TCP
    #[arg(long = "tcp_bs", default_value_t = 1024 * 1024)]
    tcp_bs: i32,

    /// Максимальное окно TCP
    #[arg(long = "tcp_mw", default_value_t = 20000)]
    tcp_mw: i32,

    /// Время повторной отправки TCP, мс
    #[arg(long = "tcp_rst", default_value_t = 400)]
    tcp_rst: i32,

    /// Порог сжатия данных TCP (0 — без сжатия)
    #[arg(long = "tcp_gz", default_value_t = 0)]
    tcp_gz: i32,

    /// Печатать статистику TCP
    #[arg(long = "tcp_stat", default_value_t = 0)]
    tcp_stat: i32,

    /// Уровень логирования
    #[arg(long = "loglevel", default_value = "info")]
    loglevel: String,

    /// Не печатать вывод
    #[arg(long = "noprint", default_value_t = 0)]
    noprint: i32,

    /// Включить SOCKS5
    #[arg(long = "sock5", default_value_t = 0)]
    sock5: i32,

    /// Имя пользователя SOCKS5
    #[arg(long = "s5user", default_value = "")]
    s5user: String,

    /// Пароль SOCKS5
    #[arg(long = "s5pass", default_value = "")]
    s5pass: String,

    /// Максимум соединений (0 — без ограничения)
    #[arg(long = "maxconn", default_value_t = 0)]
    maxconn: i32,

    /// Таймаут установления соединения сервером к цели, мс
    #[arg(long = "conntt", default_value_t = 1000)]
    conntt: i32,

    /// Форвардинг TCP через прокси (socks5://host:port или http://host:port)
    #[arg(long = "forward", default_value = "")]
    forward: String,

    /// SOCKS5-фильтр (не поддерживается в этом порте, см. README)
    #[arg(long = "s5filter", default_value = "")]
    s5filter: String,

    /// Файл данных фильтра SOCKS5 (не используется)
    #[arg(long = "s5ftfile", default_value = "GeoLite2-Country.mmdb")]
    s5ftfile: String,
}

/// Совместимость с CLI оригинала (Go `flag`): длинные флаги там пишутся с одним
/// дефисом (`-type`, `-sock5`, `-tcp`...). Превращаем `-name` в `--name` для
/// многобуквенных имён, оставляя короткие `-l`/`-s`/`-t` и числа (`-1`) как есть.
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

    let level = if args.noprint > 0 {
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

    // Проверка параметров шифрования.
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

    if !args.s5filter.is_empty() {
        log::warn!(
            "-s5filter не поддерживается в этом порте (требует GeoIP); весь трафик форвардится"
        );
    }

    log::info!("start... key {}", args.key);

    let result = if args.r#type == "server" {
        run_server(&args, crypto)
    } else {
        run_client(&args, crypto)
    };

    if let Err(e) = result {
        log::error!("ERROR: {e}");
        std::process::exit(1);
    }
}

fn run_server(args: &Args, crypto: Option<Crypto>) -> anyhow::Result<()> {
    let forward = forward::parse_forward_url(&args.forward)?;
    if forward.is_some() {
        log::info!("Forward proxy configured: {}", args.forward);
    }
    let cfg = server::ServerConfig {
        icmp_listen: args.icmp_listen.clone(),
        key: args.key,
        maxconn: args.maxconn,
        connect_timeout: args.conntt,
    };
    let srv = server::Server::new(cfg, crypto, forward)?;
    srv.run()
}

fn run_client(args: &Args, crypto: Option<Crypto>) -> anyhow::Result<()> {
    if args.listen.is_empty() || args.server.is_empty() {
        anyhow::bail!("client requires -l and -s");
    }
    let mut tcp = args.tcp;
    if args.sock5 != 0 {
        tcp = 1;
    }
    if args.sock5 == 0 && args.target.is_empty() {
        anyhow::bail!("client requires -t (target) unless -sock5 is set");
    }
    if args.tcp_mw * 10 > proto::FRAME_MAX_ID {
        anyhow::bail!("tcp win too big, max = {}", proto::FRAME_MAX_ID / 10);
    }

    let (buffersize, maxwin, resend, compress, stat) = if tcp > 0 {
        (args.tcp_bs, args.tcp_mw, args.tcp_rst, args.tcp_gz, args.tcp_stat)
    } else {
        (0, 0, 0, 0, 0)
    };

    let cfg = client::ClientConfig {
        listen: args.listen.clone(),
        server: args.server.clone(),
        target: args.target.clone(),
        timeout: args.timeout,
        key: args.key,
        icmp_listen: args.icmp_listen.clone(),
        tcpmode: tcp,
        buffersize,
        maxwin,
        resend,
        compress,
        stat,
        sock5: args.sock5,
        maxconn: args.maxconn,
        s5user: args.s5user.clone(),
        s5pass: args.s5pass.clone(),
    };
    let cli = client::Client::new(cfg, crypto)?;
    cli.run()
}

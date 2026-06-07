//! pingtunnel — туннелирование TCP/SOCKS5 поверх ICMP (async, tokio).
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
    about = "Туннелирование TCP/SOCKS5 трафика поверх ICMP (async, порт esrrhs/pingtunnel)",
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

    let workers = num_cpus::get().max(1);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let result = rt.block_on(async move {
        if args.r#type == "server" {
            run_server(args, crypto).await
        } else {
            run_client(args, crypto).await
        }
    });

    if let Err(e) = result {
        log::error!("ERROR: {e}");
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

async fn run_server(args: Args, crypto: Option<Crypto>) -> anyhow::Result<()> {
    let forward = forward::parse_forward_url(&args.forward)?;
    if forward.is_some() {
        log::info!("Forward proxy configured: {}", args.forward);
    }
    let cfg = server::ServerConfig {
        icmp_listen: args.icmp_listen.clone(),
        key: args.key,
        maxconn: args.maxconn,
        connect_timeout: args.conntt,
        frame_size: frame_size(args.jumbo),
    };
    let srv = server::Server::new(cfg, crypto, forward)?;
    srv.run().await
}

async fn run_client(args: Args, crypto: Option<Crypto>) -> anyhow::Result<()> {
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
    if args.tcp_mw * 10 > proto::FRAME_MAX_ID {
        anyhow::bail!("tcp win too big, max = {}", proto::FRAME_MAX_ID / 10);
    }

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
    };
    let cli = client::Client::new(cfg, crypto)?;
    cli.run().await
}

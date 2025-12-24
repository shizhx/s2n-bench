use clap::{Parser, ValueEnum};
use socket2::Socket as Socket2;
use socket2::{Domain, Protocol, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::interval;

#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    Client,
    Server,
}

#[derive(Clone, Debug, ValueEnum)]
enum Scene {
    #[value(name = "udp")]
    Udp,
    #[value(name = "quic-dgram")]
    QuicDgram,
}

#[derive(Parser, Debug)]
#[command(name = "s2n-bench")]
#[command(about = "Network throughput testing tool", long_about = None)]
struct Args {
    /// Operation mode: client or server
    #[arg(value_enum, long)]
    mode: Mode,

    /// Test scene: udp (default: udp)
    #[arg(value_enum, long, default_value = "udp")]
    scene: Scene,

    /// Host address for server binding or client connection (default: 127.0.0.1)
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Port number for listening (server) or target (client)
    #[arg(short, long)]
    port: u16,

    /// Packet size in bytes (default: 1024)
    #[arg(short = 's', long, default_value = "1024")]
    packet_size: usize,

    /// Path to certificate file (required for quic-dgram)
    #[arg(long)]
    cert_file: Option<String>,

    /// Path to private key file (required for quic-dgram)
    #[arg(long)]
    key_file: Option<String>,
}

/// 启动统计任务，定时打印吞吐量信息
async fn start_stats_task(
    bytes_counter: Arc<AtomicU64>,
    stats_type: &str,
) -> tokio::task::JoinHandle<()> {
    let stats_type = stats_type.to_string();
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(1));
        let mut last_bytes = 0u64;

        loop {
            interval.tick().await;
            let current_bytes = bytes_counter.load(Ordering::Relaxed);
            let bytes_per_sec = current_bytes - last_bytes;
            let total_mb = current_bytes as f64 / (1024.0 * 1024.0);
            let mb_per_sec = bytes_per_sec as f64 / (1024.0 * 1024.0);

            println!(
                "Total {}: {:.2} MB, Speed: {:.2} MB/s",
                stats_type, total_mb, mb_per_sec
            );
            last_bytes = current_bytes;
        }
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // console_subscriber::init();
    let args = Args::parse();

    match (args.mode, args.scene) {
        (Mode::Server, Scene::Udp) => run_udp_server(&args.host, args.port).await?,
        (Mode::Client, Scene::Udp) => {
            run_udp_client(&args.host, args.port, args.packet_size).await?
        }
        (Mode::Server, Scene::QuicDgram) => {
            let cert_file = args
                .cert_file
                .ok_or("Certificate file is required for QUIC server")?;
            let key_file = args
                .key_file
                .ok_or("Private key file is required for QUIC server")?;
            run_quic_dgram_server(&args.host, args.port, &cert_file, &key_file).await?
        }
        (Mode::Client, Scene::QuicDgram) => {
            run_quic_dgram_client(&args.host, args.port, args.packet_size).await?
        }
    }

    Ok(())
}

/// UDP 服务器实现
async fn run_udp_server(host: &str, port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("{}:{}", host, port);
    let socket = UdpSocket::bind(&addr).await?;
    println!("UDP server listening on {}", addr);

    let bytes_received = Arc::new(AtomicU64::new(0));
    let bytes_received_clone = Arc::clone(&bytes_received);

    // 启动统计任务
    let _stats_handle = start_stats_task(bytes_received_clone, "received").await;

    let mut buf = vec![0u8; 65536]; // UDP 最大包大小

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, _addr)) => {
                bytes_received.fetch_add(len as u64, Ordering::Relaxed);
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
            }
        }
    }
}

/// UDP 客户端实现
async fn run_udp_client(
    host: &str,
    port: u16,
    packet_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_addr = format!("{}:{}", host, port);
    let server_addr: SocketAddr = target_addr.parse()?;
    let local_addr = "0.0.0.0:0";
    let socket = UdpSocket::bind(local_addr).await?;

    println!(
        "UDP client connecting to {} (packet size: {} bytes)",
        target_addr, packet_size
    );

    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_sent_clone = Arc::clone(&bytes_sent);

    // 创建测试数据包
    let packet_data = vec![0xAB; packet_size];

    // 启动统计任务
    let _stats_handle = start_stats_task(bytes_sent_clone, "sent").await;

    loop {
        match socket.send_to(&packet_data, server_addr).await {
            Ok(sent_bytes) => {
                bytes_sent.fetch_add(sent_bytes as u64, Ordering::Relaxed);
            }
            Err(e) => {
                eprintln!("Error sending packet: {}", e);
            }
        }

        // 添加微小延迟以避免过度占用 CPU
        // tokio::task::yield_now().await;
    }
}

/// QUIC 数据报服务器实现
async fn run_quic_dgram_server(
    host: &str,
    port: u16,
    cert_file: &str,
    key_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = format!("{}:{}", host, port).parse()?;
    let socket = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    // 2. 设置缓冲区
    if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
        eprintln!("Warning: Failed to set send buffer size: {}", e);
    }
    if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("Warning: Failed to set receive buffer size: {}", e);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;

    let std_sock: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_sock)?;

    println!("QUIC datagram server listening on {}", addr);
    let bytes_received = Arc::new(AtomicU64::new(0));
    let bytes_received_clone = Arc::clone(&bytes_received);

    // 启动统计任务
    let _stats_handle = start_stats_task(bytes_received_clone, "received").await;

    todo!()
}

/// QUIC 数据报客户端实现
async fn run_quic_dgram_client(
    host: &str,
    port: u16,
    packet_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let target_addr = format!("{}:{}", host, port);
    let server_addr: SocketAddr = target_addr.parse()?;
    let local_addr: SocketAddr = "0.0.0.0:0".parse()?;

    let socket = Socket2::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    // 2. 设置缓冲区
    if let Err(e) = socket.set_send_buffer_size(4 * 1024 * 1024) {
        eprintln!("Warning: Failed to set send buffer size: {}", e);
    }
    if let Err(e) = socket.set_recv_buffer_size(4 * 1024 * 1024) {
        eprintln!("Warning: Failed to set receive buffer size: {}", e);
    }
    socket.set_nonblocking(true)?;
    socket.bind(&local_addr.into())?;

    let std_sock: std::net::UdpSocket = socket.into();
    let socket = UdpSocket::from_std(std_sock)?;

    println!(
        "QUIC datagram client connecting to {} (packet size: {} bytes)",
        target_addr, packet_size
    );

    let bytes_sent = Arc::new(AtomicU64::new(0));
    let bytes_sent_clone = Arc::clone(&bytes_sent);

    // 创建测试数据包
    let packet_data = vec![0xAB; packet_size];

    // 启动统计任务
    let _stats_handle = start_stats_task(bytes_sent_clone, "sent").await;

    socket.connect(server_addr).await.unwrap();
    todo!()
}

use bytes::Bytes;
use clap::{Parser, ValueEnum};
use s2n_quic::Client;
use s2n_quic::client::Connect;
use s2n_quic::provider::datagram::default::{Endpoint, Receiver, Sender};
use s2n_quic::{Server, provider::io::tokio::Builder as IoBuilder};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::Poll;
use std::time::Duration;
use tokio::time::interval;

#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    #[value(name = "client")]
    Client,
    #[value(name = "server")]
    Server,
}

#[derive(Clone, Debug, ValueEnum)]
enum Scene {
    #[value(name = "stream")]
    Stream,
    #[value(name = "dgram")]
    Dgram,
}

#[derive(Parser, Debug)]
#[command(name = "s2n-bench")]
#[command(about = "Network throughput testing tool", long_about = None)]
struct Args {
    /// Running mode: client or server
    #[arg(short, long)]
    mode: Mode,

    /// Listen or connect address (ip:port)
    #[arg(value_enum, short, long)]
    addr: String,

    /// Test scenario: stream or dgram
    #[arg(value_enum, short = 's', long)]
    scene: Scene,

    /// Packet size in bytes
    #[arg(short = 'p', long, default_value = "1350")]
    packet_size: usize,

    /// CA certificate path (client mode)
    #[arg(long, default_value = "./ca.crt")]
    ca: String,

    /// Server certificate path
    #[arg(long, default_value = "./server.crt")]
    cert: String,

    /// Server private key path
    #[arg(long, default_value = "./server.key")]
    key: String,

    /// QUIC congestion control algorithm (cubic, bbr, newreno)
    #[arg(long = "cc", default_value = "cubic", value_parser = ["cubic", "bbr", "newreno"])]
    pub congestion_algorithm: String,
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
            let mb_per_sec = bytes_per_sec as f64 / (1000.0 * 1000.0) * 8.0;

            println!(
                "Total {}: {:.2} MB, Speed: {:.2} Mbps",
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

    println!("=== Command Line Arguments ===");
    println!("Mode: {:?}", args.mode);
    println!("Addr: {:?}", args.addr);
    println!("Scene: {:?}", args.scene);
    println!("Packet Size: {}", args.packet_size);
    println!("CA: {:?}", args.ca);
    println!("Cert: {:?}", args.cert);
    println!("Key: {:?}", args.key);
    println!("============================");

    match (args.mode, args.scene) {
        (Mode::Server, Scene::Dgram) => {
            run_quic_dgram_server(&args.addr, &args.cert, &args.key).await?
        }
        (Mode::Client, Scene::Dgram) => {
            run_quic_dgram_client(&args.addr, &args.ca, args.packet_size).await?
        }
        (Mode::Client, Scene::Stream) => todo!(),
        (Mode::Server, Scene::Stream) => todo!(),
    }

    Ok(())
}

/// QUIC 数据报服务器实现
async fn run_quic_dgram_server(
    addr: &str,
    cert_file: &str,
    key_file: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = addr.parse()?;
    let io = IoBuilder::default()
        .with_receive_address(addr)?
        .with_send_buffer_size(4 * 1024 * 1024)?
        .with_recv_buffer_size(4 * 1024 * 1024)?
        .with_base_mtu(1500)?
        .with_initial_mtu(1500)?
        .build()
        .unwrap();
    // Create a datagram provider that has recv queue capacity
    let datagram_provider = Endpoint::builder()
        .with_recv_capacity(65536)?
        .build()
        .unwrap();
    let mut server = Server::builder()
        .with_tls((Path::new(cert_file), Path::new(key_file)))?
        .with_io(io)?
        .with_datagram(datagram_provider)?
        .start()
        .unwrap();

    println!("QUIC datagram server listening on {}", addr);
    let bytes_received = Arc::new(AtomicU64::new(0));

    // 启动统计任务
    let _stats_handle = start_stats_task(Arc::clone(&bytes_received), "received").await;

    while let Some(mut connection) = server.accept().await {
        connection.keep_alive(true).unwrap();
        // spawn a new task for the connection
        let bytes_clone = Arc::clone(&bytes_received);
        tokio::spawn(async move {
            println!("Connection accepted from {:?}", connection.remote_addr());
            loop {
                let recv_result = futures::future::poll_fn(|ctx| {
                    // datagram_mut takes a closure which calls the requested datagram function. The type
                    // of the closure parameter should be either the datagram Sender type or the
                    // datagram Receiver type. The datagram_mut function will check this type against
                    // its stored datagram Sender and Receiver, and if the type matches, the requested
                    // function will execute. Here, that requested function is poll_recv_datagram.
                    match connection
                        .datagram_mut(|recv: &mut Receiver| recv.poll_recv_datagram(ctx))
                    {
                        // If the function is successfully called on the provider, it will return Poll<Bytes>.
                        // Here we send an Ok() to wrap around the Bytes so the poll_fn doesn't complain.
                        Ok(poll_value) => poll_value.map(Ok),
                        // The datagram_mut function may return a query error if it can't find the type
                        // referenced in the closure. Here we wrap the error in a Poll::Ready enum so the
                        // poll_fn doesn't complain.
                        Err(query_err) => Poll::Ready(Err(query_err)),
                    }
                })
                .await;

                match recv_result {
                    Ok(value) => match value {
                        Ok(bytes) => {
                            bytes_clone.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                        }
                        Err(err) => {
                            eprintln!("Failed to receive datagram: {err:?}");
                        }
                    },
                    Err(err) => {
                        eprintln!("Failed to query datagram receiver: {err:?}");
                    }
                }
            }
        });
    }

    todo!()
}

/// QUIC 数据报客户端实现
async fn run_quic_dgram_client(
    addr: &str,
    ca: &str,
    packet_size: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: SocketAddr = addr.parse()?;
    let io = IoBuilder::default()
        .with_receive_address("0.0.0.0:0".parse()?)?
        .with_base_mtu(1500)?
        .with_initial_mtu(1500)?
        .with_send_buffer_size(4 * 1024 * 1024)?
        .with_recv_buffer_size(4 * 1024 * 1024)?
        .build()?;
    // Create a datagram provider that has recv queue capacity
    let datagram_provider = Endpoint::builder()
        .with_send_capacity(65536)?
        .build()
        .unwrap();

    let client = Client::builder()
        .with_tls(Path::new(ca))?
        .with_io(io)?
        .with_datagram(datagram_provider)?
        .start()
        .unwrap();

    let bytes_sent = Arc::new(AtomicU64::new(0));

    // 创建测试数据包
    let packet_data = Bytes::from(vec![0xAB; packet_size]);

    let connect = Connect::new(addr).with_server_name("localhost");
    let connection = client.connect(connect).await?;

    println!("Success to connect to {addr:?}");

    // 启动统计任务
    let _stats_handle = start_stats_task(Arc::clone(&bytes_sent), "sent").await;

    loop {
        let send_result = futures::future::poll_fn(|ctx| {
            // datagram_mut takes a closure which calls the requested datagram function. The type
            // of the closure parameter should be either the datagram Sender type or the
            // datagram Receiver type. The datagram_mut function will check this type against
            // its stored datagram Sender and Receiver, and if the type matches, the requested
            // function will execute. Here, that requested function is poll_recv_datagram.
            match connection.datagram_mut(|send: &mut Sender| {
                send.poll_send_datagram(&mut Bytes::clone(&packet_data), ctx)
            }) {
                // If the function is successfully called on the provider, it will return Poll<Bytes>.
                // Here we send an Ok() to wrap around the Bytes so the poll_fn doesn't complain.
                Ok(poll_value) => poll_value.map(Ok),
                // The datagram_mut function may return a query error if it can't find the type
                // referenced in the closure. Here we wrap the error in a Poll::Ready enum so the
                // poll_fn doesn't complain.
                Err(query_err) => Poll::Ready(Err(query_err)),
            }
        })
        .await;
        match send_result {
            Ok(value) => match value {
                Ok(_) => {
                    bytes_sent.fetch_add(packet_size as u64, Ordering::Relaxed);
                }
                Err(err) => {
                    eprintln!("Failed to send datagram: {err:?}");
                }
            },
            Err(err) => {
                eprintln!("Failed to query datagram sender: {err:?}");
            }
        }
    }
}

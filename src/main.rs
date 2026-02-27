//! # minecraft_mitm
//!
//! A Minecraft man-in-the-middle proxy for inspecting and logging packets.
//!
//! Sits between a Minecraft client and server, forwarding traffic transparently
//! while optionally logging packets to stdout and/or dumping them to a newline-
//! delimited JSON file for offline analysis.
//!
//! **Note:** Online-mode (encryption) is not supported. The target server must
//! run in offline mode or use a plugin that bypasses authentication.
//!
//! Repository: <https://github.com/kauri-off/minecraft_mitm>

use clap::Parser;
use minecraft_protocol::packet::{RawPacket, UncompressedPacket};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
use tokio::{
    fs::OpenOptions,
    io::AsyncWriteExt,
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::Mutex,
};
use tracing::{error, info};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};

use crate::packets::p774::{c2s, s2c};

mod packets;

#[derive(Parser, Clone)]
#[command(
    name = "minecraft_mitm",
    version,
    about = "A Minecraft man-in-the-middle proxy for inspecting and logging packets.",
    long_about = "Sits between a Minecraft client and server, forwarding traffic \
                  transparently. Supports stdout logging of clientbound/serverbound \
                  packets and optional JSON file dumping for offline analysis.\n\n\
                  Online-mode (encryption) is not supported — the backend server \
                  must run in offline mode."
)]
struct Args {
    /// Address and port for the proxy to listen on (e.g. 0.0.0.0:25565)
    #[arg(long)]
    bind: String,

    /// Backend server address to forward connections to (e.g. server.example.com:25565)
    #[arg(long)]
    connect_addr: String,

    /// Server address written into the forwarded handshake packet
    #[arg(long)]
    handshake_ip: String,

    /// Server port written into the forwarded handshake packet
    #[arg(long)]
    handshake_port: i32,

    /// Log clientbound (server → client) packets to stdout
    #[arg(long)]
    cb: bool,

    /// Log serverbound (client → server) packets to stdout
    #[arg(long)]
    sb: bool,

    /// Path to a file where all packets are appended as newline-delimited JSON
    #[arg(long)]
    dump_json: Option<String>,
}

/// A shared, async-safe handle to a JSON dump file.
type DumpFile = Arc<Mutex<tokio::fs::File>>;

/// The record written to the JSON dump file for each packet.
#[derive(Serialize)]
struct PacketRecord<'a> {
    direction: &'a str,
    packet_id: i32,
    length: usize,
    payload: &'a [u8],
    timestamp: String,
}

/// Append one packet record to the dump file as a single JSON line.
async fn dump_packet(file: &DumpFile, record: PacketRecord<'_>) {
    let mut line = serde_json::to_string(&record).unwrap_or_default();
    line.push('\n');
    let mut guard = file.lock().await;
    let _ = guard.write_all(line.as_bytes()).await;
}

#[tokio::main]
async fn main() {
    tracing_subscriber::registry().with(fmt::layer()).init();
    let args = Args::parse();

    // Open (or create) the JSON dump file once and share the handle across tasks.
    let dump_file: Option<DumpFile> = if let Some(ref path) = args.dump_json {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .unwrap_or_else(|e| panic!("Failed to open dump file {path:?}: {e}"));
        info!("Dumping packets to: {}", path);
        Some(Arc::new(Mutex::new(file)))
    } else {
        None
    };

    let listener = TcpListener::bind(&args.bind).await.unwrap();

    info!("Started listening on: {}", args.bind);
    while let Ok((stream, addr)) = listener.accept().await {
        info!("New connection from: {}", addr);
        tokio::spawn(router(stream, args.clone(), dump_file.clone()));
    }
}

async fn router(mut stream: TcpStream, args: Args, dump_file: Option<DumpFile>) {
    let handshake: c2s::Handshake = RawPacket::read_async(&mut stream)
        .await
        .unwrap()
        .as_uncompressed()
        .unwrap()
        .deserialize_payload()
        .unwrap();

    match handshake.intent.0 {
        1 => handle_status(stream).await,
        2 => handle_login(stream, args, handshake, dump_file).await,
        3 => todo!(),
        _ => unreachable!(),
    }
}

async fn handle_status(mut stream: TcpStream) {
    while let Ok(packet) = RawPacket::read_async(&mut stream).await {
        let packet = packet.as_uncompressed().unwrap();
        match packet.packet_id {
            c2s::StatusRequest::PACKET_ID => {
                UncompressedPacket::from_packet(&s2c::StatusResponse {
                    response: json!({
                      "version": {
                        "name": "1.21.11",
                        "protocol": 774
                      },
                      "players": {
                        "max": 20,
                        "online": 0
                      },
                      "description": "A Minecraft Server",
                    })
                    .to_string(),
                })
                .unwrap()
                .write_async(&mut stream)
                .await
                .unwrap();
            }
            c2s::PingRequest::PACKET_ID => packet.write_async(&mut stream).await.unwrap(),
            _ => unreachable!(),
        }
    }
}

async fn handle_login(
    mut client_stream: TcpStream,
    args: Args,
    handshake: c2s::Handshake,
    dump_file: Option<DumpFile>,
) {
    info!(protocol = handshake.protocol_version.0);
    let mut server_stream = TcpStream::connect(&args.connect_addr).await.unwrap();

    let handshake = c2s::Handshake {
        protocol_version: handshake.protocol_version,
        server_address: args.handshake_ip,
        server_port: args.handshake_port as u16,
        intent: handshake.intent,
    };

    UncompressedPacket::from_packet(&handshake)
        .unwrap()
        .write_async(&mut server_stream)
        .await
        .unwrap();

    let packet = RawPacket::read_async(&mut client_stream)
        .await
        .unwrap()
        .as_uncompressed()
        .unwrap();

    info!(
        direction = format!("{:?}", Dir::ServerBound),
        packet_id = packet.packet_id,
        length = packet.payload.len(),
        payload = format!("{:?}", packet.payload)
    );

    let login_start: c2s::LoginStart = packet.deserialize_payload().unwrap();

    UncompressedPacket::from_packet(&login_start)
        .unwrap()
        .write_async(&mut server_stream)
        .await
        .unwrap();

    let mut threshold: Option<i32> = None;

    loop {
        let packet = RawPacket::read_async(&mut server_stream)
            .await
            .unwrap()
            .uncompress(threshold)
            .unwrap();

        info!(
            direction = format!("{:?}", Dir::ClientBound),
            packet_id = packet.packet_id,
            length = packet.payload.len(),
            payload = format!("{:?}", packet.payload)
        );

        match packet.packet_id {
            s2c::LoginDisconnect::PACKET_ID => {
                error!(
                    "Disconnected: {}",
                    packet
                        .deserialize_payload::<s2c::LoginDisconnect>()
                        .unwrap()
                        .reason
                );
                return;
            }
            s2c::EncryptionRequest::PACKET_ID => {
                error!("EncryptionRequest | Unsupported");
                return;
            }
            s2c::SetCompression::PACKET_ID => {
                let compression: s2c::SetCompression = packet.deserialize_payload().unwrap();
                threshold = Some(compression.threshold.0);
                packet.write_async(&mut client_stream).await.unwrap();
            }
            s2c::LoginFinished::PACKET_ID => {
                packet
                    .to_raw_packet_compressed(threshold)
                    .unwrap()
                    .write_async(&mut client_stream)
                    .await
                    .unwrap();
                break;
            }
            _ => unreachable!(),
        }
    }

    let (client_read, client_write) = client_stream.into_split();
    let (server_read, server_write) = server_stream.into_split();

    let sb_handler = tokio::spawn(handle_half(
        client_read,
        server_write,
        threshold,
        Direction {
            dir: Dir::ServerBound,
            log: args.sb,
        },
        dump_file.clone(),
    ));

    let cb_handler = tokio::spawn(handle_half(
        server_read,
        client_write,
        threshold,
        Direction {
            dir: Dir::ClientBound,
            log: args.cb,
        },
        dump_file.clone(),
    ));

    let _ = tokio::join!(sb_handler, cb_handler);
}

struct Direction {
    dir: Dir,
    log: bool,
}

#[derive(Debug)]
enum Dir {
    ClientBound,
    ServerBound,
}

async fn handle_half(
    mut reader: OwnedReadHalf,
    mut writer: OwnedWriteHalf,
    threshold: Option<i32>,
    direction: Direction,
    dump_file: Option<DumpFile>,
) {
    let dir_str: String = format!("{:?}", direction.dir);
    while let Ok(packet) = RawPacket::read_async(&mut reader).await {
        let uncompressed = packet.uncompress(threshold).unwrap();

        if direction.log {
            info!(
                direction = dir_str,
                packet_id = uncompressed.packet_id,
                length = uncompressed.payload.len(),
                payload = format!("{:?}", uncompressed.payload)
            );
        }

        if let Some(ref file) = dump_file {
            dump_packet(
                file,
                PacketRecord {
                    direction: &dir_str,
                    packet_id: uncompressed.packet_id,
                    length: uncompressed.payload.len(),
                    payload: &uncompressed.payload,
                    timestamp: chrono::Utc::now()
                        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                },
            )
            .await;
        }

        uncompressed
            .to_raw_packet_compressed(threshold)
            .unwrap()
            .write_async(&mut writer)
            .await
            .unwrap();
    }
}

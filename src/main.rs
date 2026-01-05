mod cache;
mod network;
mod packet;
mod resolver;

use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;

use cache::{cache_cleanup, DnsCache, CACHE_CLEANUP_INTERVAL_SECS};
use packet::{build_response, parse_packet, print_record, qtype_to_string};
use resolver::{resolve_recursive, ResolveResult, ROOT_SERVERS};

fn handle_query(
    query_data: Vec<u8>,
    src: std::net::SocketAddr,
    socket: Arc<UdpSocket>,
    cache: DnsCache,
) {
    let query_packet = parse_packet(&query_data);

    println!(
        "Transaction ID: 0x{:04X}",
        query_packet.header.transaction_id
    );

    for question in &query_packet.questions {
        println!(
            "Query: {} {} class={}",
            question.name,
            qtype_to_string(question.qtype),
            question.qclass
        );

        let mut resolving = HashSet::new();
        let result = resolve_recursive(&question.name, question.qtype, 0, &mut resolving, &cache);

        match result {
            ResolveResult::Answer(records) => {
                println!("\n=== FINAL ANSWER ===");
                for record in &records {
                    print_record(record, "ANSWER");
                }

                let response = build_response(&query_data, &records, 0);
                if let Err(e) = socket.send_to(&response, src) {
                    println!("Failed to send response: {}", e);
                } else {
                    println!("Sent {} bytes to client", response.len());
                }
            }
            ResolveResult::NxDomain => {
                println!("\n=== NXDOMAIN ===");
                let response = build_response(&query_data, &[], 3);
                let _ = socket.send_to(&response, src);
            }
            ResolveResult::ServFail(err) => {
                println!("\n=== SERVFAIL: {} ===", err);
                let response = build_response(&query_data, &[], 2);
                let _ = socket.send_to(&response, src);
            }
        }
    }
}

fn main() -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:2100")?);
    let cache: DnsCache = Arc::new(RwLock::new(HashMap::new()));

    println!("DNS recursive resolver listening on 127.0.0.1:2100");
    println!("Using {} root servers", ROOT_SERVERS.len());
    println!("Features: TTL cache, TCP fallback, bailiwick checking, txid validation");

    let cleanup_cache = Arc::clone(&cache);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(CACHE_CLEANUP_INTERVAL_SECS));
        cache_cleanup(&cleanup_cache);
        let cache_read = cleanup_cache.read().unwrap();
        println!("[Cache] {} entries after cleanup", cache_read.len());
    });

    let pending_queries: Arc<Mutex<HashSet<u16>>> = Arc::new(Mutex::new(HashSet::new()));

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = socket.recv_from(&mut buf)?;
        println!("\n{}", "=".repeat(60));
        println!("Received {} bytes from {}", len, src);

        let query_data = buf[..len].to_vec();
        let socket_clone = Arc::clone(&socket);
        let cache_clone = Arc::clone(&cache);
        let pending_clone = Arc::clone(&pending_queries);

        if len >= 2 {
            let txid = u16::from_be_bytes([query_data[0], query_data[1]]);
            let mut pending = pending_clone.lock().unwrap();
            if pending.contains(&txid) {
                println!("Duplicate query (txid {:04X}), ignoring", txid);
                continue;
            }
            pending.insert(txid);
        }

        thread::spawn(move || {
            handle_query(query_data.clone(), src, socket_clone, cache_clone);

            if query_data.len() >= 2 {
                let txid = u16::from_be_bytes([query_data[0], query_data[1]]);
                let mut pending = pending_clone.lock().unwrap();
                pending.remove(&txid);
            }
        });
    }
}

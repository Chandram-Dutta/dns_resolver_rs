use std::io::{Read as IoRead, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

use crate::packet::{is_truncated, parse_packet, DnsPacket};

pub const TIMEOUT_MS: u64 = 2000;
pub const MAX_RETRIES: u32 = 2;

pub fn send_query_tcp(server_ip: &str, query: &[u8]) -> Result<DnsPacket, String> {
    let server_addr = format!("{}:53", server_ip);
    let mut stream =
        TcpStream::connect_timeout(&server_addr.parse().unwrap(), Duration::from_millis(TIMEOUT_MS))
            .map_err(|e| format!("TCP connect failed: {}", e))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .map_err(|e| format!("set timeout failed: {}", e))?;

    let len = query.len() as u16;
    stream
        .write_all(&len.to_be_bytes())
        .map_err(|e| format!("TCP write length failed: {}", e))?;
    stream
        .write_all(query)
        .map_err(|e| format!("TCP write query failed: {}", e))?;

    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| format!("TCP read length failed: {}", e))?;
    let response_len = u16::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; response_len];
    stream
        .read_exact(&mut response_buf)
        .map_err(|e| format!("TCP read response failed: {}", e))?;

    Ok(parse_packet(&response_buf))
}

pub fn send_query_udp(
    server_ip: &str,
    query: &[u8],
    expected_txid: u16,
) -> Result<(DnsPacket, bool), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind failed: {}", e))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .map_err(|e| format!("set timeout failed: {}", e))?;

    let server_addr = format!("{}:53", server_ip);
    let mut response_buf = [0u8; 512];

    for attempt in 1..=MAX_RETRIES {
        socket
            .send_to(query, &server_addr)
            .map_err(|e| format!("send failed: {}", e))?;

        match socket.recv_from(&mut response_buf) {
            Ok((len, src)) => {
                if !src.to_string().starts_with(server_ip) {
                    continue;
                }

                if len < 12 {
                    continue;
                }

                let received_txid = u16::from_be_bytes([response_buf[0], response_buf[1]]);
                if received_txid != expected_txid {
                    println!(
                        "    WARNING: Transaction ID mismatch (expected {:04X}, got {:04X})",
                        expected_txid, received_txid
                    );
                    continue;
                }

                let packet = parse_packet(&response_buf[..len]);
                let truncated = is_truncated(&packet);
                return Ok((packet, truncated));
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if attempt < MAX_RETRIES {
                    continue;
                }
            }
            Err(e) => {
                return Err(format!("recv failed: {}", e));
            }
        }
    }

    Err(format!("timeout querying {}", server_ip))
}

pub fn send_query(server_ip: &str, query: &[u8], expected_txid: u16) -> Result<DnsPacket, String> {
    match send_query_udp(server_ip, query, expected_txid) {
        Ok((packet, truncated)) => {
            if truncated {
                println!("    Response truncated, retrying with TCP...");
                send_query_tcp(server_ip, query)
            } else {
                Ok(packet)
            }
        }
        Err(e) => Err(e),
    }
}

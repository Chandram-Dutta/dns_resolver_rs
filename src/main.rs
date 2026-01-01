use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

const UPSTREAM_DNS: &str = "8.8.8.8:53";
const TIMEOUT_MS: u64 = 2000;
const MAX_RETRIES: u32 = 3;

#[derive(Debug)]
struct DnsHeader {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authority: u16,
    additional: u16,
}

#[derive(Debug)]
struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug)]
struct DnsRecord {
    name: String,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: RData,
}

#[derive(Debug)]
enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    MX {
        preference: u16,
        exchange: String,
    },
    TXT(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR(String),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Unknown(Vec<u8>),
}

#[derive(Debug)]
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authority: Vec<DnsRecord>,
    additional: Vec<DnsRecord>,
}

fn parse_header(data: &[u8]) -> DnsHeader {
    DnsHeader {
        transaction_id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        questions: u16::from_be_bytes([data[4], data[5]]),
        answers: u16::from_be_bytes([data[6], data[7]]),
        authority: u16::from_be_bytes([data[8], data[9]]),
        additional: u16::from_be_bytes([data[10], data[11]]),
    }
}

fn parse_name(data: &[u8], offset: &mut usize) -> String {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut local_offset = *offset;

    loop {
        if local_offset >= data.len() {
            break;
        }

        let len = data[local_offset] as usize;

        if (len & 0xC0) == 0xC0 {
            if local_offset + 1 >= data.len() {
                break;
            }
            let pointer = u16::from_be_bytes([data[local_offset], data[local_offset + 1]]) & 0x3FFF;
            if !jumped {
                *offset = local_offset + 2;
            }
            local_offset = pointer as usize;
            jumped = true;
            continue;
        }

        if len == 0 {
            if !jumped {
                *offset = local_offset + 1;
            }
            break;
        }

        local_offset += 1;
        if local_offset + len > data.len() {
            break;
        }

        let label = String::from_utf8_lossy(&data[local_offset..local_offset + len]).to_string();
        labels.push(label);
        local_offset += len;
    }

    labels.join(".")
}

fn parse_question(data: &[u8], offset: &mut usize) -> DnsQuestion {
    let name = parse_name(data, offset);
    let qtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
    let qclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
    *offset += 4;

    DnsQuestion {
        name,
        qtype,
        qclass,
    }
}

fn parse_record(data: &[u8], offset: &mut usize) -> DnsRecord {
    let name = parse_name(data, offset);
    let rtype = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
    let rclass = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
    let ttl = u32::from_be_bytes([
        data[*offset + 4],
        data[*offset + 5],
        data[*offset + 6],
        data[*offset + 7],
    ]);
    let rdlength = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]) as usize;
    *offset += 10;

    let rdata_start = *offset;
    let rdata = match rtype {
        1 if rdlength == 4 => {
            // A record
            let addr = Ipv4Addr::new(
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            );
            *offset += 4;
            RData::A(addr)
        }
        28 if rdlength == 16 => {
            // AAAA record
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[*offset..*offset + 16]);
            *offset += 16;
            RData::AAAA(Ipv6Addr::from(octets))
        }
        2 => {
            // NS record
            let ns = parse_name(data, offset);
            RData::NS(ns)
        }
        5 => {
            // CNAME record
            let cname = parse_name(data, offset);
            RData::CNAME(cname)
        }
        12 => {
            // PTR record
            let ptr = parse_name(data, offset);
            RData::PTR(ptr)
        }
        15 => {
            // MX record
            let preference = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            let exchange = parse_name(data, offset);
            RData::MX {
                preference,
                exchange,
            }
        }
        16 => {
            // TXT record
            let mut txt = String::new();
            let end = rdata_start + rdlength;
            while *offset < end {
                let txt_len = data[*offset] as usize;
                *offset += 1;
                if *offset + txt_len <= end {
                    txt.push_str(&String::from_utf8_lossy(&data[*offset..*offset + txt_len]));
                    *offset += txt_len;
                }
            }
            RData::TXT(txt)
        }
        6 => {
            // SOA record
            let mname = parse_name(data, offset);
            let rname = parse_name(data, offset);
            let serial = u32::from_be_bytes([
                data[*offset],
                data[*offset + 1],
                data[*offset + 2],
                data[*offset + 3],
            ]);
            let refresh = u32::from_be_bytes([
                data[*offset + 4],
                data[*offset + 5],
                data[*offset + 6],
                data[*offset + 7],
            ]);
            let retry = u32::from_be_bytes([
                data[*offset + 8],
                data[*offset + 9],
                data[*offset + 10],
                data[*offset + 11],
            ]);
            let expire = u32::from_be_bytes([
                data[*offset + 12],
                data[*offset + 13],
                data[*offset + 14],
                data[*offset + 15],
            ]);
            let minimum = u32::from_be_bytes([
                data[*offset + 16],
                data[*offset + 17],
                data[*offset + 18],
                data[*offset + 19],
            ]);
            *offset += 20;
            RData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            }
        }
        33 => {
            // SRV record
            let priority = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
            let weight = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
            let port = u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]);
            *offset += 6;
            let target = parse_name(data, offset);
            RData::SRV {
                priority,
                weight,
                port,
                target,
            }
        }
        _ => {
            let raw = data[*offset..*offset + rdlength].to_vec();
            *offset += rdlength;
            RData::Unknown(raw)
        }
    };

    *offset = rdata_start + rdlength;

    DnsRecord {
        name,
        rtype,
        rclass,
        ttl,
        rdata,
    }
}

fn parse_packet(data: &[u8]) -> DnsPacket {
    let header = parse_header(data);
    let mut offset = 12;

    let mut questions = Vec::new();
    for _ in 0..header.questions {
        questions.push(parse_question(data, &mut offset));
    }

    let mut answers = Vec::new();
    for _ in 0..header.answers {
        answers.push(parse_record(data, &mut offset));
    }

    let mut authority = Vec::new();
    for _ in 0..header.authority {
        authority.push(parse_record(data, &mut offset));
    }

    let mut additional = Vec::new();
    for _ in 0..header.additional {
        if offset >= data.len() {
            break;
        }
        additional.push(parse_record(data, &mut offset));
    }

    DnsPacket {
        header,
        questions,
        answers,
        authority,
        additional,
    }
}

fn qtype_to_string(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

fn print_record(record: &DnsRecord, section: &str) {
    let rtype_str = qtype_to_string(record.rtype);
    let rdata_str = match &record.rdata {
        RData::A(addr) => addr.to_string(),
        RData::AAAA(addr) => addr.to_string(),
        RData::CNAME(name) => name.clone(),
        RData::NS(name) => name.clone(),
        RData::MX {
            preference,
            exchange,
        } => format!("{} {}", preference, exchange),
        RData::TXT(txt) => format!("\"{}\"", txt),
        RData::PTR(name) => name.clone(),
        RData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => format!(
            "{} {} {} {} {} {} {}",
            mname, rname, serial, refresh, retry, expire, minimum
        ),
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{} {} {} {}", priority, weight, port, target),
        RData::Unknown(data) => format!("<{} bytes>", data.len()),
    };

    println!(
        "  {} {} {} {} TTL={} {}",
        section, record.name, rtype_str, record.rclass, record.ttl, rdata_str
    );
}

fn forward_query(query: &[u8]) -> Result<Vec<u8>, String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind failed: {}", e))?;

    socket
        .set_read_timeout(Some(Duration::from_millis(TIMEOUT_MS)))
        .map_err(|e| format!("set timeout failed: {}", e))?;

    let mut response_buf = [0u8; 512];

    for attempt in 1..=MAX_RETRIES {
        socket
            .send_to(query, UPSTREAM_DNS)
            .map_err(|e| format!("send failed: {}", e))?;

        match socket.recv_from(&mut response_buf) {
            Ok((len, _)) => {
                return Ok(response_buf[..len].to_vec());
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                println!("  Timeout on attempt {}/{}", attempt, MAX_RETRIES);
                continue;
            }
            Err(e) => {
                return Err(format!("recv failed: {}", e));
            }
        }
    }

    Err("all retries failed".to_string())
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:2100")?;
    println!("DNS forwarding proxy listening on 127.0.0.1:2100");
    println!("Forwarding queries to {}", UPSTREAM_DNS);

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = socket.recv_from(&mut buf)?;
        println!("\n--- Received {} bytes from {} ---", len, src);

        let query_packet = parse_packet(&buf[..len]);

        println!(
            "Transaction ID: 0x{:04X}",
            query_packet.header.transaction_id
        );
        println!("Flags: 0x{:04X}", query_packet.header.flags);

        for question in &query_packet.questions {
            println!(
                "Query: {} {} class={}",
                question.name,
                qtype_to_string(question.qtype),
                question.qclass
            );
        }

        println!("Forwarding to {}...", UPSTREAM_DNS);

        match forward_query(&buf[..len]) {
            Ok(response) => {
                let response_packet = parse_packet(&response);

                let rcode = response_packet.header.flags & 0x000F;
                println!(
                    "Response: {} answers, {} authority, {} additional, rcode={}",
                    response_packet.header.answers,
                    response_packet.header.authority,
                    response_packet.header.additional,
                    rcode
                );

                if response_packet.header.transaction_id != query_packet.header.transaction_id {
                    println!(
                        "WARNING: Transaction ID mismatch! Expected 0x{:04X}, got 0x{:04X}",
                        query_packet.header.transaction_id, response_packet.header.transaction_id
                    );
                }

                for record in &response_packet.answers {
                    print_record(record, "ANSWER");
                }
                for record in &response_packet.authority {
                    print_record(record, "AUTH");
                }
                for record in &response_packet.additional {
                    print_record(record, "EXTRA");
                }

                socket.send_to(&response, src)?;
                println!("Forwarded {} bytes back to client", response.len());
            }
            Err(e) => {
                println!("Forward failed: {}", e);
                // Sending SERVFAIL response
                let mut servfail = buf[..len].to_vec();
                if servfail.len() >= 4 {
                    servfail[2] = 0x81; // QR=1, RD=1
                    servfail[3] = 0x82; // RA=1, RCODE=2 (SERVFAIL)
                }
                socket.send_to(&servfail, src)?;
            }
        }
    }
}

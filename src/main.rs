use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::time::Duration;

const TIMEOUT_MS: u64 = 2000;
const MAX_RETRIES: u32 = 2;
const MAX_RECURSION_DEPTH: u32 = 20;

const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
];

#[derive(Debug)]
struct DnsHeader {
    transaction_id: u16,
    flags: u16,
    questions: u16,
    answers: u16,
    authority: u16,
    additional: u16,
}

#[derive(Debug, Clone)]
struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

#[derive(Debug, Clone)]
struct DnsRecord {
    name: String,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: RData,
}

#[derive(Debug, Clone)]
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
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[*offset..*offset + 16]);
            *offset += 16;
            RData::AAAA(Ipv6Addr::from(octets))
        }
        2 => {
            let ns = parse_name(data, offset);
            RData::NS(ns)
        }
        5 => {
            let cname = parse_name(data, offset);
            RData::CNAME(cname)
        }
        12 => {
            let ptr = parse_name(data, offset);
            RData::PTR(ptr)
        }
        15 => {
            let preference = u16::from_be_bytes([data[*offset], data[*offset + 1]]);
            *offset += 2;
            let exchange = parse_name(data, offset);
            RData::MX {
                preference,
                exchange,
            }
        }
        16 => {
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

fn build_query(name: &str, qtype: u16, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    // Header
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1 (recursion desired, though servers may ignore)
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section - encode name
    for label in name.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0); // Root label

    packet.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    packet
}

fn send_query(server_ip: &str, query: &[u8]) -> Result<DnsPacket, String> {
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
            Ok((len, _)) => {
                return Ok(parse_packet(&response_buf[..len]));
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

fn get_rcode(packet: &DnsPacket) -> u16 {
    packet.header.flags & 0x000F
}

fn is_authoritative(packet: &DnsPacket) -> bool {
    (packet.header.flags & 0x0400) != 0
}

fn find_glue_a(additional: &[DnsRecord], ns_name: &str) -> Option<Ipv4Addr> {
    let ns_lower = ns_name.to_lowercase();
    for record in additional {
        if record.rtype == 1 && record.name.to_lowercase() == ns_lower {
            if let RData::A(addr) = &record.rdata {
                return Some(*addr);
            }
        }
    }
    None
}

fn extract_ns_names(authority: &[DnsRecord]) -> Vec<String> {
    authority
        .iter()
        .filter_map(|r| {
            if r.rtype == 2 {
                if let RData::NS(name) = &r.rdata {
                    return Some(name.clone());
                }
            }
            None
        })
        .collect()
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

#[derive(Debug)]
enum ResolveResult {
    Answer(Vec<DnsRecord>),
    NxDomain,
    ServFail(String),
}

fn resolve_recursive(
    name: &str,
    qtype: u16,
    depth: u32,
    resolving: &mut HashSet<String>,
) -> ResolveResult {
    if depth > MAX_RECURSION_DEPTH {
        return ResolveResult::ServFail("max recursion depth exceeded".to_string());
    }

    let cache_key = format!("{}:{}", name.to_lowercase(), qtype);
    if resolving.contains(&cache_key) {
        return ResolveResult::ServFail("loop detected".to_string());
    }
    resolving.insert(cache_key.clone());

    let indent = "  ".repeat(depth as usize);
    println!(
        "{}[depth={}] Resolving {} {}",
        indent,
        depth,
        name,
        qtype_to_string(qtype)
    );

    let mut servers: Vec<String> = ROOT_SERVERS.iter().map(|s| s.to_string()).collect();
    let mut server_label = "ROOT";

    let transaction_id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        & 0xFFFF) as u16;

    let query = build_query(name, qtype, transaction_id);

    loop {
        let mut last_error = String::new();
        let mut response: Option<DnsPacket> = None;

        for server_ip in &servers {
            println!("{}  Querying {} ({})...", indent, server_ip, server_label);

            match send_query(server_ip, &query) {
                Ok(packet) => {
                    response = Some(packet);
                    break;
                }
                Err(e) => {
                    println!("{}    Failed: {}", indent, e);
                    last_error = e;
                }
            }
        }

        let packet = match response {
            Some(p) => p,
            None => {
                resolving.remove(&cache_key);
                return ResolveResult::ServFail(last_error);
            }
        };

        let rcode = get_rcode(&packet);

        if rcode == 3 {
            println!("{}  NXDOMAIN", indent);
            resolving.remove(&cache_key);
            return ResolveResult::NxDomain;
        }

        if rcode != 0 {
            println!("{}  RCODE={}", indent, rcode);
            resolving.remove(&cache_key);
            return ResolveResult::ServFail(format!("rcode={}", rcode));
        }

        if !packet.answers.is_empty() {
            for answer in &packet.answers {
                if answer.rtype == 5 && qtype != 5 {
                    if let RData::CNAME(cname) = &answer.rdata {
                        println!("{}  CNAME -> {}", indent, cname);
                        let cname_result = resolve_recursive(cname, qtype, depth + 1, resolving);
                        resolving.remove(&cache_key);
                        return match cname_result {
                            ResolveResult::Answer(mut records) => {
                                let mut full_answer = vec![answer.clone()];
                                full_answer.append(&mut records);
                                ResolveResult::Answer(full_answer)
                            }
                            other => other,
                        };
                    }
                }
            }

            let matching: Vec<DnsRecord> = packet
                .answers
                .iter()
                .filter(|r| r.rtype == qtype || r.rtype == 5)
                .cloned()
                .collect();

            if !matching.is_empty() {
                println!("{}  Got {} answer(s)", indent, matching.len());
                resolving.remove(&cache_key);
                return ResolveResult::Answer(matching);
            }
        }

        let ns_names = extract_ns_names(&packet.authority);

        if ns_names.is_empty() {
            if is_authoritative(&packet) {
                println!("{}  Authoritative: no data", indent);
                resolving.remove(&cache_key);
                return ResolveResult::Answer(vec![]);
            }
            resolving.remove(&cache_key);
            return ResolveResult::ServFail("no answers or referral".to_string());
        }

        println!("{}  Referral to {} NS(s)", indent, ns_names.len());

        let mut next_servers: Vec<String> = Vec::new();

        for ns_name in &ns_names {
            if let Some(ip) = find_glue_a(&packet.additional, ns_name) {
                println!("{}    {} -> {} (glue)", indent, ns_name, ip);
                next_servers.push(ip.to_string());
            }
        }

        if next_servers.is_empty() {
            for ns_name in ns_names.iter().take(2) {
                println!("{}    Resolving NS: {}", indent, ns_name);
                match resolve_recursive(ns_name, 1, depth + 1, resolving) {
                    ResolveResult::Answer(records) => {
                        for r in records {
                            if let RData::A(addr) = r.rdata {
                                println!("{}      {} -> {}", indent, ns_name, addr);
                                next_servers.push(addr.to_string());
                            }
                        }
                    }
                    _ => {
                        println!("{}      Failed to resolve {}", indent, ns_name);
                    }
                }
                if !next_servers.is_empty() {
                    break;
                }
            }
        }

        if next_servers.is_empty() {
            resolving.remove(&cache_key);
            return ResolveResult::ServFail("could not resolve any nameservers".to_string());
        }

        servers = next_servers;
        server_label = "NS";
    }
}

fn build_response(original_query: &[u8], answers: &[DnsRecord], rcode: u16) -> Vec<u8> {
    let mut response = original_query.to_vec();

    if response.len() < 12 {
        return response;
    }

    // Set QR=1 (response), RD=1, RA=1
    response[2] = 0x81;
    response[3] = 0x80 | (rcode as u8 & 0x0F);

    // Update answer count
    let ancount = answers.len() as u16;
    response[6] = (ancount >> 8) as u8;
    response[7] = (ancount & 0xFF) as u8;

    // Clear authority and additional
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;

    for record in answers {
        for label in record.name.split('.') {
            if !label.is_empty() {
                response.push(label.len() as u8);
                response.extend_from_slice(label.as_bytes());
            }
        }
        response.push(0);

        response.extend_from_slice(&record.rtype.to_be_bytes());
        response.extend_from_slice(&record.rclass.to_be_bytes());
        response.extend_from_slice(&record.ttl.to_be_bytes());

        // RDATA
        match &record.rdata {
            RData::A(addr) => {
                response.extend_from_slice(&4u16.to_be_bytes());
                response.extend_from_slice(&addr.octets());
            }
            RData::AAAA(addr) => {
                response.extend_from_slice(&16u16.to_be_bytes());
                response.extend_from_slice(&addr.octets());
            }
            RData::CNAME(name) | RData::NS(name) | RData::PTR(name) => {
                let mut rdata = Vec::new();
                for label in name.split('.') {
                    if !label.is_empty() {
                        rdata.push(label.len() as u8);
                        rdata.extend_from_slice(label.as_bytes());
                    }
                }
                rdata.push(0);
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(&rdata);
            }
            RData::MX {
                preference,
                exchange,
            } => {
                let mut rdata = Vec::new();
                rdata.extend_from_slice(&preference.to_be_bytes());
                for label in exchange.split('.') {
                    if !label.is_empty() {
                        rdata.push(label.len() as u8);
                        rdata.extend_from_slice(label.as_bytes());
                    }
                }
                rdata.push(0);
                response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
                response.extend_from_slice(&rdata);
            }
            RData::TXT(txt) => {
                let txt_bytes = txt.as_bytes();
                let rdlength = 1 + txt_bytes.len();
                response.extend_from_slice(&(rdlength as u16).to_be_bytes());
                response.push(txt_bytes.len() as u8);
                response.extend_from_slice(txt_bytes);
            }
            RData::Unknown(data) => {
                response.extend_from_slice(&(data.len() as u16).to_be_bytes());
                response.extend_from_slice(data);
            }
            _ => {
                response.extend_from_slice(&0u16.to_be_bytes());
            }
        }
    }

    response
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:2100")?;
    println!("DNS recursive resolver listening on 127.0.0.1:2100");
    println!("Using {} root servers", ROOT_SERVERS.len());

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = socket.recv_from(&mut buf)?;
        println!("\n{}", "=".repeat(60));
        println!("Received {} bytes from {}", len, src);

        let query_packet = parse_packet(&buf[..len]);

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
            let result = resolve_recursive(&question.name, question.qtype, 0, &mut resolving);

            match result {
                ResolveResult::Answer(records) => {
                    println!("\n=== FINAL ANSWER ===");
                    for record in &records {
                        print_record(record, "ANSWER");
                    }

                    let response = build_response(&buf[..len], &records, 0);
                    socket.send_to(&response, src)?;
                    println!("Sent {} bytes to client", response.len());
                }
                ResolveResult::NxDomain => {
                    println!("\n=== NXDOMAIN ===");
                    let response = build_response(&buf[..len], &[], 3);
                    socket.send_to(&response, src)?;
                }
                ResolveResult::ServFail(err) => {
                    println!("\n=== SERVFAIL: {} ===", err);
                    let response = build_response(&buf[..len], &[], 2);
                    socket.send_to(&response, src)?;
                }
            }
        }
    }
}

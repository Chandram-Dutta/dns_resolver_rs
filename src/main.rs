use std::collections::{HashMap, HashSet};
use std::io::{Read as IoRead, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT_MS: u64 = 2000;
const MAX_RETRIES: u32 = 2;
const MAX_RECURSION_DEPTH: u32 = 20;
const CACHE_CLEANUP_INTERVAL_SECS: u64 = 60;

const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
];

#[derive(Debug, Clone)]
struct CacheEntry {
    records: Vec<DnsRecord>,
    inserted_at: Instant,
    min_ttl: u32,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed().as_secs() >= self.min_ttl as u64
    }

    fn adjust_ttls(&self) -> Vec<DnsRecord> {
        let elapsed = self.inserted_at.elapsed().as_secs() as u32;
        self.records
            .iter()
            .map(|r| {
                let mut record = r.clone();
                record.ttl = record.ttl.saturating_sub(elapsed);
                record
            })
            .collect()
    }
}

type DnsCache = Arc<RwLock<HashMap<String, CacheEntry>>>;

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
        if offset >= data.len() {
            break;
        }
        answers.push(parse_record(data, &mut offset));
    }

    let mut authority = Vec::new();
    for _ in 0..header.authority {
        if offset >= data.len() {
            break;
        }
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

fn generate_transaction_id() -> u16 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64,
    );
    hasher.finish() as u16
}

fn build_query(name: &str, qtype: u16, transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in name.split('.') {
        if !label.is_empty() {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
    }
    packet.push(0);

    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    packet
}

fn is_truncated(packet: &DnsPacket) -> bool {
    (packet.header.flags & 0x0200) != 0
}

fn send_query_tcp(server_ip: &str, query: &[u8]) -> Result<DnsPacket, String> {
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

fn send_query_udp(
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

fn send_query(server_ip: &str, query: &[u8], expected_txid: u16) -> Result<DnsPacket, String> {
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

fn get_rcode(packet: &DnsPacket) -> u16 {
    packet.header.flags & 0x000F
}

fn is_authoritative(packet: &DnsPacket) -> bool {
    (packet.header.flags & 0x0400) != 0
}

fn is_in_bailiwick(ns_name: &str, zone: &str) -> bool {
    let ns_lower = ns_name.to_lowercase();
    let zone_lower = zone.to_lowercase();

    if zone_lower.is_empty() {
        return true;
    }

    ns_lower == zone_lower || ns_lower.ends_with(&format!(".{}", zone_lower))
}

fn find_glue_a(additional: &[DnsRecord], ns_name: &str, zone: &str) -> Option<Ipv4Addr> {
    if !is_in_bailiwick(ns_name, zone) {
        return None;
    }

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

fn find_glue_aaaa(additional: &[DnsRecord], ns_name: &str, zone: &str) -> Option<Ipv6Addr> {
    if !is_in_bailiwick(ns_name, zone) {
        return None;
    }

    let ns_lower = ns_name.to_lowercase();
    for record in additional {
        if record.rtype == 28 && record.name.to_lowercase() == ns_lower {
            if let RData::AAAA(addr) = &record.rdata {
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

fn extract_zone_from_authority(authority: &[DnsRecord]) -> String {
    authority
        .iter()
        .find(|r| r.rtype == 2)
        .map(|r| r.name.clone())
        .unwrap_or_default()
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

fn cache_lookup(cache: &DnsCache, name: &str, qtype: u16) -> Option<Vec<DnsRecord>> {
    let cache_key = format!("{}:{}", name.to_lowercase(), qtype);
    let cache_read = cache.read().unwrap();
    if let Some(entry) = cache_read.get(&cache_key) {
        if !entry.is_expired() {
            return Some(entry.adjust_ttls());
        }
    }
    None
}

fn cache_insert(cache: &DnsCache, name: &str, qtype: u16, records: &[DnsRecord]) {
    if records.is_empty() {
        return;
    }

    let min_ttl = records.iter().map(|r| r.ttl).min().unwrap_or(300);
    if min_ttl == 0 {
        return;
    }

    let cache_key = format!("{}:{}", name.to_lowercase(), qtype);
    let entry = CacheEntry {
        records: records.to_vec(),
        inserted_at: Instant::now(),
        min_ttl,
    };

    let mut cache_write = cache.write().unwrap();
    cache_write.insert(cache_key, entry);
}

fn cache_cleanup(cache: &DnsCache) {
    let mut cache_write = cache.write().unwrap();
    cache_write.retain(|_, entry| !entry.is_expired());
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
    cache: &DnsCache,
) -> ResolveResult {
    if depth > MAX_RECURSION_DEPTH {
        return ResolveResult::ServFail("max recursion depth exceeded".to_string());
    }

    let cache_key = format!("{}:{}", name.to_lowercase(), qtype);

    if let Some(cached) = cache_lookup(cache, name, qtype) {
        let indent = "  ".repeat(depth as usize);
        println!(
            "{}[depth={}] Cache hit for {} {}",
            indent,
            depth,
            name,
            qtype_to_string(qtype)
        );
        return ResolveResult::Answer(cached);
    }

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
    let mut current_zone;

    loop {
        let transaction_id = generate_transaction_id();
        let query = build_query(name, qtype, transaction_id);

        let mut last_error = String::new();
        let mut response: Option<DnsPacket> = None;

        for server_ip in &servers {
            println!("{}  Querying {} ({})...", indent, server_ip, server_label);

            match send_query(server_ip, &query, transaction_id) {
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
                        let cname_result =
                            resolve_recursive(cname, qtype, depth + 1, resolving, cache);
                        resolving.remove(&cache_key);
                        return match cname_result {
                            ResolveResult::Answer(mut records) => {
                                let mut full_answer = vec![answer.clone()];
                                full_answer.append(&mut records);
                                cache_insert(cache, name, qtype, &full_answer);
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
                cache_insert(cache, name, qtype, &matching);
                resolving.remove(&cache_key);
                return ResolveResult::Answer(matching);
            }
        }

        let ns_names = extract_ns_names(&packet.authority);
        current_zone = extract_zone_from_authority(&packet.authority);

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
            if let Some(ip) = find_glue_a(&packet.additional, ns_name, &current_zone) {
                println!("{}    {} -> {} (glue A)", indent, ns_name, ip);
                next_servers.push(ip.to_string());
            }
            if let Some(ip) = find_glue_aaaa(&packet.additional, ns_name, &current_zone) {
                println!("{}    {} -> {} (glue AAAA)", indent, ns_name, ip);
            }
        }

        if next_servers.is_empty() {
            for ns_name in ns_names.iter().take(2) {
                println!("{}    Resolving NS: {}", indent, ns_name);
                match resolve_recursive(ns_name, 1, depth + 1, resolving, cache) {
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

    response[2] = 0x81;
    response[3] = 0x80 | (rcode as u8 & 0x0F);

    let ancount = answers.len() as u16;
    response[6] = (ancount >> 8) as u8;
    response[7] = (ancount & 0xFF) as u8;

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
        let result =
            resolve_recursive(&question.name, question.qtype, 0, &mut resolving, &cache);

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

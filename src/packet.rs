use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: u16,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: RData,
}

#[derive(Debug, Clone)]
pub enum RData {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    MX { preference: u16, exchange: String },
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
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

pub fn parse_header(data: &[u8]) -> DnsHeader {
    DnsHeader {
        transaction_id: u16::from_be_bytes([data[0], data[1]]),
        flags: u16::from_be_bytes([data[2], data[3]]),
        questions: u16::from_be_bytes([data[4], data[5]]),
        answers: u16::from_be_bytes([data[6], data[7]]),
        authority: u16::from_be_bytes([data[8], data[9]]),
        additional: u16::from_be_bytes([data[10], data[11]]),
    }
}

pub fn parse_name(data: &[u8], offset: &mut usize) -> String {
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

pub fn parse_question(data: &[u8], offset: &mut usize) -> DnsQuestion {
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

pub fn parse_record(data: &[u8], offset: &mut usize) -> DnsRecord {
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

pub fn parse_packet(data: &[u8]) -> DnsPacket {
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

pub fn generate_transaction_id() -> u16 {
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

pub fn build_query(name: &str, qtype: u16, transaction_id: u16) -> Vec<u8> {
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

pub fn build_response(original_query: &[u8], answers: &[DnsRecord], rcode: u16) -> Vec<u8> {
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

pub fn is_truncated(packet: &DnsPacket) -> bool {
    (packet.header.flags & 0x0200) != 0
}

pub fn get_rcode(packet: &DnsPacket) -> u16 {
    packet.header.flags & 0x000F
}

pub fn is_authoritative(packet: &DnsPacket) -> bool {
    (packet.header.flags & 0x0400) != 0
}

pub fn qtype_to_string(qtype: u16) -> &'static str {
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

pub fn print_record(record: &DnsRecord, section: &str) {
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

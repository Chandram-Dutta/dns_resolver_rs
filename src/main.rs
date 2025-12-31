use std::net::UdpSocket;

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
struct DnsPacket {
    header: DnsHeader,
    questions: Vec<DnsQuestion>,
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

fn parse_packet(data: &[u8]) -> DnsPacket {
    let header = parse_header(data);
    let mut offset = 12; // Header is always 12 bytes

    let mut questions = Vec::new();
    for _ in 0..header.questions {
        questions.push(parse_question(data, &mut offset));
    }

    DnsPacket { header, questions }
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

fn build_response(query: &[u8], packet: &DnsPacket) -> Vec<u8> {
    let mut response = Vec::new();

    response.extend_from_slice(&packet.header.transaction_id.to_be_bytes());

    let query_flags = packet.header.flags;
    let rd = query_flags & 0x0100;
    let response_flags: u16 = 0x8000 | rd;
    response.extend_from_slice(&response_flags.to_be_bytes());

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());

    let question_start = 12;
    let mut offset = question_start;
    for _ in 0..packet.header.questions {
        while offset < query.len() && query[offset] != 0 {
            if (query[offset] & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += 1 + query[offset] as usize;
        }
        if offset < query.len() && query[offset] == 0 {
            offset += 1;
        }
        offset += 4;
    }
    response.extend_from_slice(&query[question_start..offset]);

    response.extend_from_slice(&[0xC0, 0x0C]);

    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());

    response.extend_from_slice(&300u32.to_be_bytes());

    response.extend_from_slice(&4u16.to_be_bytes());
    response.extend_from_slice(&[1, 2, 3, 4]);

    response
}

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:2100")?;
    println!("DNS server listening on 127.0.0.1:2100");

    let mut buf = [0u8; 512];
    loop {
        let (len, src) = socket.recv_from(&mut buf)?;
        println!("\nReceived {} bytes from {}", len, src);

        let packet = parse_packet(&buf[..len]);

        println!("Transaction ID: 0x{:04X}", packet.header.transaction_id);
        println!("Flags: 0x{:04X}", packet.header.flags);

        for question in &packet.questions {
            println!(
                "Query for: {}, type {}",
                question.name,
                qtype_to_string(question.qtype)
            );
        }

        let response = build_response(&buf[..len], &packet);
        socket.send_to(&response, src)?;
        println!("Sent response with 1.2.3.4 ({} bytes)", response.len());
    }
}

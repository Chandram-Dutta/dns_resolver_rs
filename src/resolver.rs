use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::cache::{cache_insert, cache_lookup, DnsCache};
use crate::network::send_query;
use crate::packet::{
    build_query, generate_transaction_id, get_rcode, is_authoritative, qtype_to_string, DnsPacket,
    DnsRecord, RData,
};

pub const MAX_RECURSION_DEPTH: u32 = 20;

pub const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",     // a.root-servers.net
    "199.9.14.201",   // b.root-servers.net
    "192.33.4.12",    // c.root-servers.net
    "199.7.91.13",    // d.root-servers.net
    "192.203.230.10", // e.root-servers.net
];

#[derive(Debug)]
pub enum ResolveResult {
    Answer(Vec<DnsRecord>),
    NxDomain,
    ServFail(String),
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

pub fn resolve_recursive(
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

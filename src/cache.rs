use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::packet::DnsRecord;

pub const CACHE_CLEANUP_INTERVAL_SECS: u64 = 60;

#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub records: Vec<DnsRecord>,
    pub inserted_at: Instant,
    pub min_ttl: u32,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        self.inserted_at.elapsed().as_secs() >= self.min_ttl as u64
    }

    pub fn adjust_ttls(&self) -> Vec<DnsRecord> {
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

pub type DnsCache = Arc<RwLock<HashMap<String, CacheEntry>>>;

pub fn cache_lookup(cache: &DnsCache, name: &str, qtype: u16) -> Option<Vec<DnsRecord>> {
    let cache_key = format!("{}:{}", name.to_lowercase(), qtype);
    let cache_read = cache.read().unwrap();
    if let Some(entry) = cache_read.get(&cache_key) {
        if !entry.is_expired() {
            return Some(entry.adjust_ttls());
        }
    }
    None
}

pub fn cache_insert(cache: &DnsCache, name: &str, qtype: u16, records: &[DnsRecord]) {
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

pub fn cache_cleanup(cache: &DnsCache) {
    let mut cache_write = cache.write().unwrap();
    cache_write.retain(|_, entry| !entry.is_expired());
}

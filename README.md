# dns_resolver_rs

A DNS recursive resolver written in Rust using only the standard library.

## Features

- True recursive resolution from root servers
- DNS packet parsing with compression pointer support
- Record types: A, AAAA, CNAME, NS, MX, TXT, SOA, PTR, SRV
- TTL-based caching with automatic cleanup
- TCP fallback for truncated responses
- CNAME chain following
- Bailiwick checking for glue records
- Transaction ID validation
- Loop detection (max depth: 20)

## Usage

```bash
cargo run --release
```

The server listens on `127.0.0.1:2100`.

## Testing

```bash
dig @127.0.0.1 -p 2100 example.com
dig @127.0.0.1 -p 2100 google.com MX
dig @127.0.0.1 -p 2100 cloudflare.com AAAA
```

## Stress Testing

Run the included stress test to benchmark performance:

```bash
# Terminal 1: Start the resolver
cargo run --release

# Terminal 2: Run stress test
./stress_test.sh
```

### Configuration

Edit variables at the top of `stress_test.sh`:

| Variable | Default | Description |
|----------|---------|-------------|
| `CONCURRENT` | 10 | Max concurrent queries |
| `QUERIES_PER_BATCH` | 50 | Queries per batch |
| `TOTAL_BATCHES` | 5 | Number of batches |
| `TIMEOUT` | 5 | Query timeout (seconds) |

### Metrics Reported

- **Success rate**: Percentage of queries returning NOERROR or NXDOMAIN
- **QPS**: Queries per second throughput
- **Latency**: Min, avg, max, p50, p95, p99 (in seconds)

## Project Structure

```
src/
├── main.rs      # Server loop, query handling
├── packet.rs    # DNS types and parsing
├── cache.rs     # TTL cache implementation
├── network.rs   # UDP/TCP query functions
└── resolver.rs  # Recursive resolution logic
```

## License

MIT

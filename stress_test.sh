#!/bin/bash

# DNS Resolver Stress Test
# Tests the resolver at 127.0.0.1:2100

SERVER="127.0.0.1"
PORT="2100"
CONCURRENT=50
QUERIES_PER_BATCH=50
TOTAL_BATCHES=10
TIMEOUT=10

DOMAINS=(
    "example.com" "google.com" "github.com" "cloudflare.com" "amazon.com"
    "microsoft.com" "apple.com" "netflix.com" "twitter.com" "facebook.com"
    "reddit.com" "stackoverflow.com" "wikipedia.org" "youtube.com" "linkedin.com"
    "instagram.com" "twitch.tv" "discord.com" "slack.com" "zoom.us"
)

RECORD_TYPES=("A" "AAAA" "MX" "TXT" "NS")

RESULTS_DIR=$(mktemp -d)
START_TIME=$(date +%s.%N)

success=0
failed=0
total=0

run_query() {
    local domain=$1
    local type=$2
    local id=$3
    local start=$(date +%s.%N)

    result=$(dig @$SERVER -p $PORT $domain $type +time=$TIMEOUT +tries=1 2>&1)
    local end=$(date +%s.%N)
    local duration=$(echo "$end - $start" | bc)

    if echo "$result" | grep -q "NOERROR\|NXDOMAIN"; then
        echo "OK $duration" > "$RESULTS_DIR/$id"
    else
        echo "FAIL $duration" > "$RESULTS_DIR/$id"
    fi
}

echo "=========================================="
echo "  DNS Resolver Stress Test"
echo "=========================================="
echo "Server: $SERVER:$PORT"
echo "Concurrent queries: $CONCURRENT"
echo "Queries per batch: $QUERIES_PER_BATCH"
echo "Total batches: $TOTAL_BATCHES"
echo "Total queries: $((QUERIES_PER_BATCH * TOTAL_BATCHES))"
echo "=========================================="
echo ""

for batch in $(seq 1 $TOTAL_BATCHES); do
    echo "Batch $batch/$TOTAL_BATCHES..."

    for i in $(seq 1 $QUERIES_PER_BATCH); do
        domain=${DOMAINS[$RANDOM % ${#DOMAINS[@]}]}
        type=${RECORD_TYPES[$RANDOM % ${#RECORD_TYPES[@]}]}
        query_id="${batch}_${i}"

        run_query "$domain" "$type" "$query_id" &

        # Limit concurrent queries
        while [ $(jobs -r | wc -l) -ge $CONCURRENT ]; do
            sleep 0.05
        done
    done

    wait
done

END_TIME=$(date +%s.%N)
TOTAL_TIME=$(echo "$END_TIME - $START_TIME" | bc)

# Collect results
declare -a latencies
for f in "$RESULTS_DIR"/*; do
    [ -f "$f" ] || continue
    read status latency < "$f"
    total=$((total + 1))
    if [ "$status" = "OK" ]; then
        success=$((success + 1))
        latencies+=("$latency")
    else
        failed=$((failed + 1))
    fi
done

# Calculate statistics
if [ ${#latencies[@]} -gt 0 ]; then
    sorted=($(printf '%s\n' "${latencies[@]}" | sort -n))
    count=${#sorted[@]}

    sum=0
    for l in "${latencies[@]}"; do
        sum=$(echo "$sum + $l" | bc)
    done
    avg=$(echo "scale=3; $sum / $count" | bc)

    min=${sorted[0]}
    max=${sorted[$((count - 1))]}
    p50=${sorted[$((count / 2))]}
    p95=${sorted[$((count * 95 / 100))]}
    p99=${sorted[$((count * 99 / 100))]}

    qps=$(echo "scale=2; $total / $TOTAL_TIME" | bc)
fi

# Print results
echo ""
echo "=========================================="
echo "  Results"
echo "=========================================="
echo "Total queries:    $total"
echo "Successful:       $success"
echo "Failed:           $failed"
echo "Success rate:     $(echo "scale=2; $success * 100 / $total" | bc)%"
echo ""
echo "Total time:       ${TOTAL_TIME}s"
echo "Queries/sec:      $qps"
echo ""
echo "Latency (seconds):"
echo "  Min:            $min"
echo "  Avg:            $avg"
echo "  Max:            $max"
echo "  P50:            $p50"
echo "  P95:            $p95"
echo "  P99:            $p99"
echo "=========================================="

# Cleanup
rm -rf "$RESULTS_DIR"

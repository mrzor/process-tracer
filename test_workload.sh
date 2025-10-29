a#!/bin/bash
# Complex workload script to test eBPF tracer
# Demonstrates parallel execution, sequential operations, and various network activities

set -e

echo "=== Starting complex workload test ==="

# Sequential operations first
echo "[Sequential] Phase 1: Initial checks..."
sleep 0.1
hostname
sleep 0.1
date
uname -a

# Parallel HTTP requests to different endpoints
echo "[Parallel] Phase 2: Parallel HTTP requests..."
curl -s https://httpbin.org/uuid > /tmp/uuid1.txt &
PID1=$!

curl -s https://httpbin.org/delay/1 > /tmp/delay1.txt &
PID2=$!

curl -s https://api.github.com/zen > /tmp/zen.txt &
PID3=$!

# While those are running, do some local work
echo "[Local] Processing while waiting for HTTP..."
for i in {1..5}; do
    echo "  Local work iteration $i"
    ls /tmp > /dev/null
    sleep 0.2
done

# Wait for all parallel HTTP requests
echo "[Wait] Waiting for parallel HTTP requests to complete..."
wait $PID1 $PID2 $PID3
echo "[Done] All HTTP requests completed"

# Sequential DNS lookups
echo "[Sequential] Phase 3: DNS lookups..."
dig +short github.com > /tmp/dns1.txt || true
dig +short google.com > /tmp/dns2.txt || true
sleep 0.1

# Parallel mixed operations
echo "[Parallel] Phase 4: Mixed parallel operations..."

# Background job 1: Multiple sequential network calls
(
    echo "  [Job1] Starting sequential network operations..."
    curl -s https://httpbin.org/ip > /tmp/ip.txt
    sleep 0.2
    curl -s https://httpbin.org/user-agent > /tmp/ua.txt
    echo "  [Job1] Complete"
) &
JOB1=$!

# Background job 2: File operations with subprocess
(
    echo "  [Job2] File operations with subprocesses..."
    find /tmp -name "*.txt" -type f | head -10 > /tmp/files.txt
    cat /tmp/files.txt | wc -l > /tmp/count.txt
    echo "  [Job2] Complete"
) &
JOB2=$!

# Background job 3: Network test with timeout
(
    echo "  [Job3] Network connectivity test..."
    timeout 2 curl -s https://httpbin.org/delay/1 > /tmp/timeout_test.txt || echo "timeout" > /tmp/timeout_test.txt
    echo "  [Job3] Complete"
) &
JOB3=$!

# Background job 4: Shell pipeline
(
    echo "  [Job4] Complex shell pipeline..."
    ps aux | grep -v grep | head -20 | awk '{print $1, $2, $11}' | sort | uniq > /tmp/processes.txt
    echo "  [Job4] Complete"
) &
JOB4=$!

# Do some work while background jobs run
echo "[Local] Main thread work while jobs run..."
sleep 0.3
echo "  Checking system info..."
cat /proc/cpuinfo | grep "model name" | head -1 || true

# Wait for all parallel jobs
echo "[Wait] Waiting for all parallel jobs..."
wait $JOB1 $JOB2 $JOB3 $JOB4
echo "[Done] All parallel jobs completed"

# Final sequential phase with nested parallelism
echo "[Sequential] Phase 5: Nested parallel operations..."
for round in {1..2}; do
    echo "  Round $round: Starting mini-parallel batch..."
    
    curl -s "https://httpbin.org/uuid" > /tmp/round_${round}_a.txt &
    curl -s "https://httpbin.org/uuid" > /tmp/round_${round}_b.txt &
    
    # Wait for this round's jobs
    wait
    
    echo "  Round $round: Batch complete"
    sleep 0.1
done

# Cleanup and summary
echo "[Cleanup] Phase 6: Collecting results..."
(
    echo "=== Workload Summary ==="
    echo "Files created:"
    ls -lh /tmp/*.txt 2>/dev/null | wc -l
    echo "Total data retrieved:"
    du -sh /tmp/*.txt 2>/dev/null | awk '{sum+=$1} END {print sum " bytes"}'
) &
wait

# Final TCP connection test
echo "[Final] Phase 7: Final connection test..."
curl -s https://httpbin.org/headers > /tmp/final_headers.txt
sleep 0.1

echo "=== Workload test complete ==="
echo "Check your OTEL collector for the full trace!"


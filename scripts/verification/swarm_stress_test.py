#!/usr/bin/env python3
"""
Swarm Stress Test — verifies worker scaling and task throughput.

Usage:
    python scripts/verification/swarm_stress_test.py \
        --url http://localhost:8000 \
        --token <api-key> \
        --targets 10 \
        --scan-type dns_scanner \
        --workers 3

The script:
  1. Optionally scales worker replicas (via docker service scale if --scale-workers)
  2. Queues N scan tasks against test/dummy targets
  3. Polls queue stats until all tasks complete or timeout
  4. Reports throughput, latency, and error counts
"""
import argparse
import sys
import time
import requests
from datetime import datetime


def parse_args():
    p = argparse.ArgumentParser(description="YADS Swarm Stress Test")
    p.add_argument("--url", default="http://localhost:8000", help="YADS base URL")
    p.add_argument("--token", required=True, help="API key (X-API-Key header)")
    p.add_argument("--targets", type=int, default=5, help="Number of targets to scan")
    p.add_argument("--scan-type", default="dns_scanner", help="Scanner module to use")
    p.add_argument("--timeout", type=int, default=300, help="Max seconds to wait for completion")
    p.add_argument("--scale-workers", type=int, default=0,
                   help="Scale yads_yads-worker service to N replicas (0 = skip)")
    p.add_argument("--service-name", default="yads_yads-worker",
                   help="Docker service name for scaling")
    return p.parse_args()


def scale_workers(service: str, replicas: int):
    import subprocess
    print(f"  Scaling {service} to {replicas} replica(s)...")
    result = subprocess.run(
        ["docker", "service", "scale", f"{service}={replicas}"],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        print(f"  WARNING: docker service scale failed: {result.stderr.strip()}")
    else:
        print(f"  OK — waiting 10s for workers to start...")
        time.sleep(10)


def get_targets(session, url: str) -> list[dict]:
    resp = session.get(f"{url}/api/v1/targets", timeout=10)
    resp.raise_for_status()
    return resp.json() if isinstance(resp.json(), list) else []


def queue_scan(session, url: str, target_id: int, scan_type: str) -> dict:
    resp = session.post(
        f"{url}/api/v1/dast/scan",
        json={"target_id": target_id, "scan_types": [scan_type]},
        timeout=10,
    )
    return resp.json()


def get_queue_stats(session, url: str) -> dict:
    resp = session.get(f"{url}/queue/stats", timeout=10)
    if resp.ok:
        return resp.json()
    return {}


def main():
    args = parse_args()
    session = requests.Session()
    session.headers["X-API-Key"] = args.token

    print(f"\n{'='*60}")
    print(f"  YADS Swarm Stress Test")
    print(f"  URL:     {args.url}")
    print(f"  Targets: {args.targets}")
    print(f"  Scanner: {args.scan_type}")
    print(f"{'='*60}\n")

    # Optional: scale workers
    if args.scale_workers > 0:
        scale_workers(args.service_name, args.scale_workers)

    # Fetch available targets
    print("Fetching targets...")
    try:
        targets = get_targets(session, args.url)
    except Exception as e:
        print(f"ERROR: Cannot fetch targets: {e}")
        sys.exit(1)

    if not targets:
        print("ERROR: No targets found. Add at least one target before running stress test.")
        sys.exit(1)

    # Select test targets (cycle if not enough)
    test_targets = [targets[i % len(targets)] for i in range(args.targets)]
    print(f"Using {len(set(t['id'] for t in test_targets))} unique target(s) "
          f"across {args.targets} scan task(s)")

    # Queue scans
    print(f"\nQueueing {args.targets} scan(s) [{args.scan_type}]...")
    queued = 0
    errors = 0
    start_time = time.time()

    for i, target in enumerate(test_targets):
        try:
            result = queue_scan(session, args.url, target["id"], args.scan_type)
            queued += 1
            if (i + 1) % 5 == 0 or i == 0:
                print(f"  [{i+1}/{args.targets}] Queued target={target.get('domain','?')} "
                      f"id={target['id']}")
        except Exception as e:
            errors += 1
            print(f"  [{i+1}/{args.targets}] ERROR: {e}")

    queue_time = time.time() - start_time
    print(f"\nQueued {queued}/{args.targets} tasks in {queue_time:.1f}s "
          f"({queued/max(queue_time, 0.001):.1f} tasks/sec)")

    if errors > 0:
        print(f"WARNING: {errors} task(s) failed to queue")

    # Poll until complete or timeout
    print(f"\nMonitoring queue (timeout: {args.timeout}s)...")
    poll_start = time.time()
    last_active = queued
    completed = 0

    while time.time() - poll_start < args.timeout:
        time.sleep(5)
        stats = get_queue_stats(session, args.url)
        active = stats.get("active", 0)
        reserved = stats.get("reserved", 0)
        total_remaining = active + reserved
        elapsed = time.time() - poll_start

        if total_remaining != last_active:
            completed = queued - total_remaining
            print(f"  [{elapsed:.0f}s] Active={active} Reserved={reserved} "
                  f"Completed~{max(0, completed)}")
            last_active = total_remaining

        if total_remaining == 0:
            break

    total_time = time.time() - start_time

    # Final report
    print(f"\n{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")
    print(f"  Total time:       {total_time:.1f}s")
    print(f"  Tasks queued:     {queued}")
    print(f"  Queue errors:     {errors}")
    print(f"  Throughput:       {queued/max(total_time, 0.001):.2f} tasks/sec")

    final_stats = get_queue_stats(session, args.url)
    print(f"  Final queue size: {final_stats.get('active', '?')} active, "
          f"{final_stats.get('reserved', '?')} reserved")

    if errors == 0 and final_stats.get("active", 1) == 0:
        print(f"\n  ✓ Stress test PASSED")
        sys.exit(0)
    else:
        print(f"\n  ✗ Stress test FAILED (errors={errors}, "
              f"remaining={final_stats.get('active', '?')})")
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Samples wazuh-manager-remoted from /proc while load runs against it, so a download test
can be read against what the server was actually doing: how many connections were open,
how many threads were live, whether descriptors or memory grew.

Everything comes from /proc, so it costs the server nothing and cannot miss time between
samples the way a percentage-based CPU reading can: CPU is a counter delta, not a probe.

Run it alongside send_download.py:

  sudo python3 monitor.py --duration 30 &
  sudo python3 send_download.py --simulate 8 --repeat 20
"""
import argparse
import os
import subprocess
import sys
import time

CLK_TCK = os.sysconf("SC_CLK_TCK")

# /proc/net/tcp state codes worth separating. A pile-up in TIME_WAIT or CLOSE_WAIT is the
# signature of connections not being closed cleanly, which a raw "established" count hides.
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}


def find_pid(pattern="wazuh-manager-remoted"):
    out = subprocess.run(["pgrep", "-f", pattern], capture_output=True, text=True, check=False)
    pids = [int(p) for p in out.stdout.split() if p.isdigit()]
    return pids[0] if pids else None


def read_status(pid):
    """VmRSS (KiB) and thread count, in one pass over /proc/<pid>/status."""
    rss = threads = None
    try:
        with open(f"/proc/{pid}/status") as handle:
            for line in handle:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("Threads:"):
                    threads = int(line.split()[1])
                if rss is not None and threads is not None:
                    break
    except OSError:
        return None, None
    return rss, threads


def read_cpu_ticks(pid):
    """utime+stime in clock ticks. A counter, so two reads give exact CPU time between them."""
    try:
        with open(f"/proc/{pid}/stat") as handle:
            fields = handle.read().rsplit(") ", 1)[1].split()
    except (OSError, IndexError):
        return None
    # After the comm field, index 11/12 are utime/stime (fields 14/15 in proc(5) terms).
    return int(fields[11]) + int(fields[12])


def read_fds(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def read_connections(port):
    """Counts sockets on `port` by TCP state, from /proc/net/tcp{,6}."""
    wanted = f"{port:04X}"
    counts = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path) as handle:
                next(handle, None)
                for line in handle:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    local_port = parts[1].split(":")[1]
                    remote_port = parts[2].split(":")[1]
                    if local_port != wanted and remote_port != wanted:
                        continue
                    state = TCP_STATES.get(parts[3], parts[3])
                    counts[state] = counts.get(state, 0) + 1
        except OSError:
            continue
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", type=int, default=None, help="PID to watch (default: find wazuh-manager-remoted).")
    parser.add_argument("--port", type=int, default=1517,
                        help="Port whose connections to count (the <remote><https><port> default).")
    parser.add_argument("--interval", type=float, default=0.1, help="Seconds between samples.")
    parser.add_argument("--duration", type=float, default=30.0, help="Seconds to sample for.")
    parser.add_argument("--quiet", action="store_true", help="Only print the summary, not the timeline.")
    args = parser.parse_args()

    pid = args.pid or find_pid()
    if not pid:
        raise SystemExit("wazuh-manager-remoted not found (use --pid)")

    rss0, threads0 = read_status(pid)
    fds0 = read_fds(pid)
    ticks0 = read_cpu_ticks(pid)
    if rss0 is None:
        raise SystemExit(f"cannot read /proc/{pid} (run as root?)")

    print(f"monitoring pid {pid} (port {args.port}) for {args.duration:g}s, every {args.interval:g}s")
    print(f"baseline: RSS {rss0 / 1024:.1f} MiB, {threads0} threads, {fds0} fds\n")
    if not args.quiet:
        print(f"{'t(s)':>6} {'RSS MiB':>8} {'thr':>4} {'fds':>5} {'estab':>6} {'tw':>4} {'other':>6}")

    samples = []
    started = time.time()
    while time.time() - started < args.duration:
        now = time.time() - started
        rss, threads = read_status(pid)
        if rss is None:
            print("process went away")
            break
        fds = read_fds(pid)
        conns = read_connections(args.port)
        estab = conns.get("ESTABLISHED", 0)
        tw = conns.get("TIME_WAIT", 0)
        other = sum(v for k, v in conns.items() if k not in ("ESTABLISHED", "TIME_WAIT", "LISTEN"))
        samples.append((now, rss, threads, fds, estab, tw, other))
        # Only print rows where something is actually happening: a live/half-closed connection,
        # or a change against the PREVIOUS sample. Comparing against the first sample instead
        # would keep printing every idle row once RSS had shifted at all.
        prev = samples[-2] if len(samples) > 1 else None
        moved = prev is None or (rss, threads, fds, estab) != (prev[1], prev[2], prev[3], prev[4])
        if not args.quiet and (estab or other or moved):
            print(f"{now:6.1f} {rss / 1024:8.1f} {threads:4d} {fds:5d} {estab:6d} {tw:4d} {other:6d}")
        time.sleep(args.interval)

    ticks1 = read_cpu_ticks(pid)
    rss1, threads1 = read_status(pid)
    fds1 = read_fds(pid)

    if not samples:
        raise SystemExit("no samples collected")

    rss_vals = [s[1] for s in samples]
    thr_vals = [s[2] for s in samples]
    fd_vals = [s[3] for s in samples]
    est_vals = [s[4] for s in samples]

    print(f"\n--- summary over {len(samples)} samples ({time.time() - started:.1f}s) ---")
    print(f"  RSS         {rss0 / 1024:7.1f} -> {rss1 / 1024:7.1f} MiB   "
          f"(min {min(rss_vals) / 1024:.1f}, peak {max(rss_vals) / 1024:.1f}, "
          f"growth {(rss1 - rss0) / 1024:+.2f})")
    print(f"  threads     {threads0:7d} -> {threads1:7d}       (min {min(thr_vals)}, peak {max(thr_vals)})")
    print(f"  fds         {fds0:7d} -> {fds1:7d}       (min {min(fd_vals)}, peak {max(fd_vals)})")
    print(f"  conns       peak established {max(est_vals)}, "
          f"mean {sum(est_vals) / len(est_vals):.1f} (while sampling)")
    if ticks0 is not None and ticks1 is not None:
        cpu_s = (ticks1 - ticks0) / CLK_TCK
        print(f"  CPU         {cpu_s:.2f}s of process time")
    # The two numbers that matter for a leak: both must come back to baseline.
    print(f"  VERDICT     fds {'OK' if fds1 <= fds0 else 'GREW by %d' % (fds1 - fds0)}, "
          f"threads {'OK' if threads1 <= threads0 else 'GREW by %d' % (threads1 - threads0)}, "
          f"RSS {'flat' if (rss1 - rss0) < 8192 else 'GREW by %.1f MiB' % ((rss1 - rss0) / 1024)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

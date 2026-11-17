# macOS process and port telemetry PoC (#41434)

Runs every macOS candidate against the same scenarios as the Windows PoC and compares the results with the driver's own log.

| File | What it does |
|---|---|
| `driver.py` | Ground truth: 410 short-lived processes with distinct exit codes, user changes through `sudo`, and 48 fast TCP/UDP ports (IPv4/IPv6, user and root) |
| `esc.c` | Endpoint Security client: `NOTIFY_EXEC/FORK/EXIT`, plus a probe of the undocumented `RESERVED_*` events |
| `nstat.c` | `NetworkStatistics` private framework (loaded with `dlopen`): socket add, description and removal in real time |
| `ports.c` | libproc port scan with PID and uid, at a given interval |
| `kq.c` | kqueue `NOTE_EXIT`/`NOTE_EXITSTATUS` on a child and a non-child |
| `run.sh` | Builds everything, runs the collectors and the driver, checks OpenBSM, and writes `out/summary.md` |
| `analyze.py` | Compares every collector with the ground truth |
| `poc.yml` | GitHub Actions job used to run it on macOS 15 and 26 (arm64 and x86_64); copy it to `.github/workflows/` with these files at the repository root |

Run `./run.sh` as a user with passwordless `sudo`. The ES client is ad-hoc signed with `es.plist`, so it only connects with SIP disabled (as on GitHub-hosted runners) until the Apple entitlement is granted.

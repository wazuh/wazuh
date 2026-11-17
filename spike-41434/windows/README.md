# Spike #41434: Windows real-time process and port telemetry (PoC code)

Proof-of-concept code used to evaluate real-time event sources for process lifecycle and port who-data on Windows. The results, the comparison matrix and the recommendation are in the Windows comment on wazuh/wazuh#41434. This is throwaway research code, not production code.

## Layout

| Path | Content |
|---|---|
| `src/etwpoc.c` | ETW real-time consumer. Starts a private session, enables the providers of the selected mode, decodes every event with TDH and prints its fields, then reports latency, lost events, CPU and memory |
| `src/invpoc.c` | Change notifications for other inventories: SCM (`NotifyServiceStatusChange`), System log 7036/7040/7045, `RegNotifyChangeKeyValue` on the `Uninstall` keys (HKLM and every loaded HKU) and on each user's AppX repository key, Security log 4720/4726/4732/4733, `NotifyIpInterfaceChange` and `NotifyUnicastIpAddressChange` |
| `src/quick.c` | Short-lived test process (under 10 ms, exit code 7) |
| `ebpf/` | eBPF for Windows programs (`SEC("process")` with ntosebpfext, `SEC("bind")`) |
| `scripts/` | Test scenarios run inside the VM; each writes a ground-truth file next to the consumer log |
| `lab/` | Helpers to copy the binaries to a VM and run a scenario over PowerShell Remoting, and to fetch the results |
| `analysis/` | Scripts that compare a consumer log with its ground truth |

## Build

Cross-compiled with MinGW (for example the `dockcross/windows-static-x64` image), into `bin/`:

```bash
mkdir -p bin
x86_64-w64-mingw32.static-gcc -O2 -Wall -municode -o bin/etwpoc.exe src/etwpoc.c -ltdh -ladvapi32 -lole32 -lpsapi
x86_64-w64-mingw32.static-gcc -O2 -Wall -municode -o bin/invpoc.exe src/invpoc.c -lwevtapi -ladvapi32 -liphlpapi -lws2_32
x86_64-w64-mingw32.static-gcc -O2 -o bin/quick.exe src/quick.c
```

The eBPF programs build with `clang -target bpf -O2 -ffreestanding` and the headers of eBPF for Windows v1.7.0 and ntosebpfext v0.7.0. The release MSI loads native programs only, so they must be converted with `bpf2c` and signed as drivers to run.

## `etwpoc.exe` modes

`etwpoc.exe <mode> <seconds> [maxprint] [buf_kb] [max_buffers] [slow_us] [decode_only] [flush_ms] [watchdog]`

| Mode | Session content |
|---|---|
| `mp` | `Microsoft-Windows-Kernel-Process` + `Microsoft-Windows-Kernel-Network` (private session) |
| `sl` | System-logger session with classic process and TCP/UDP events |
| `afd` | `Microsoft-Windows-Winsock-AFD` + `Microsoft-Windows-TCPIP`, unfiltered |
| `ports` | `Microsoft-Windows-TCPIP` filtered by event ID, with `EVENT_ENABLE_PROPERTY_SID` |
| `full2` | System logger (classic process events only) + TCPIP filtered (1008, 1009, 1123, 1124, 1391, 1396, 1397) + Kernel-Network filtered (12, 13, 15, 28, 29, 31) |
| `full3` | `full2` + Kernel-Process event 1 (full image path). This is the recommended set |
| `list` | Running ETW sessions and system-logger slots in use |

- `flush_ms` sets the flush interval in milliseconds (`EVENT_TRACE_USE_MS_FLUSH_TIMER`).
- With `watchdog` set to 1, the consumer polls the session every second and recreates it if it was stopped.

## Scenarios

The scenarios expect the binaries in `C:\poc41434` (see `lab/run.ps1 -Copy`) and must run elevated. The ones that act as SYSTEM use a one-shot scheduled task, registered with `-AllowStartIfOnBatteries`, because a VM on a laptop host reports a battery.

| Script | What it checks |
|---|---|
| `scenario.ps1` | `mp` vs `sl`: 100 `cmd /c exit 3`, TCP/UDP ports, connect/accept |
| `scenario_listen.ps1` | `afd`: listening ports with no connection |
| `scenario_ports.ps1` | `ports`: listen and bind as a user and as SYSTEM, SID property |
| `scenario_full.ps1` | Process storm in sequence and in parallel, listen with connect/accept, SYSTEM processes and port; any mode, buffer size, slow consumer, flush interval |
| `scenario_ports2.ps1` + `sys_part.ps1` | `full3`: full image path, ports open for 300 ms (TCP/UDP, IPv4/IPv6) with PID, user and close event, SYSTEM processes and ports |
| `scenario_wd.ps1` | Watchdog: stops the session with `logman` while processes run, and counts the ones missed in the gap |
| `round3.ps1`, `loss_test.ps1` | Decode cost, idle cost, slow consumer with minimal buffers, external stop |
| `scenario_udp_probe.ps1` | `afd`: which events carry the UDP bind port (Server 2012 R2 has no TCPIP 1396/1397) |
| `scenario_inv.ps1` | Services: create, start-type change, delete, start and stop; packages through registry writes |
| `scenario_inv2.ps1` | Real MSI install and uninstall (needs `7z-x64.msi` in `C:\poc41434`), per-user `Uninstall` key, AppX remove and re-register, users and groups, audit policy. `-NetworkTest` also adds and removes an IP address and changes the MTU: run it only on a disposable VM, because adding an address to a DHCP interface disables DHCP |
| `scenario_audit.ps1` | Default audit policy, and whether the account-management events are logged |
| `sysmon_test.ps1` + `sysmon41434.xml` | Sysmon events 1, 3 and 5 for the same workload |
| `ebpf_test2.ps1` | eBPF for Windows: ntosebpfext install, program load, workload, map dump |

## Analysis

```bash
python3 analysis/analyze.py  out/etw_<tag>.txt out/truth_<tag>.csv <label>   # scenario_full
python3 analysis/analyze2.py out/etw_<tag>.txt out/truth_<tag>.csv <label>   # scenario_ports2
```

`analyze2.py` resolves the PID of each port in this order:
1. the event field;
2. the latest 1391 with the same `Endpoint` before the bind, because `Endpoint` addresses are reused;
3. the event header.

It then matches that PID with the process start events to get the user, and checks for the close event.

# Enrollment Simulator

A performance testing tool for the Wazuh authentication daemon (`wazuh-manager-authd`). This simulator generates concurrent SSL connections to test agent enrollment scenarios under various load conditions.

## Overview

The enrollment simulator creates multiple threads that simultaneously attempt to register agents with the Wazuh authentication daemon. It supports various agent configurations and provides detailed performance statistics including response times, success rates, and throughput metrics.

It speaks only authd's **legacy TLS protocol on port 1515**, the one 4.x agents use: one request
line per connection, `[OSSEC PASS: <password> ]OSSEC A:'<name>' V:'<version>'[ G:'<group>']`, and a
registration counts as successful when the answer starts with `OSSEC K:`. It does not exercise the
5.x path (`POST /enroll` on the HTTPS listener, port 1517). For that path, use the
`enroll_https` step of [`tools/manager_benchmark`](../../manager_benchmark/README.md).

Against a 5.x manager the legacy listener must be up (`<auth><legacy_enrollment>`, which follows
`<remote><legacy><enabled>` when unset), and the installer's configuration sets
`<use_password>yes</use_password>`, so pass the password from `/var/wazuh-manager/etc/authd.pass`
with `--password`. Every successful registration creates a real agent (random 12-character names);
the simulator never deletes them, so remove them afterwards (for example through the server API's
`DELETE /agents`).

## Features

- **Multi-threaded simulation** with configurable thread count
- **SSL/TLS connections** to wazuh-manager-authd
- **Configurable agent scenarios**:
  - New vs. repeated agent registrations (a repeated one re-sends a name this run already used)
  - Correct vs. incorrect passwords (an incorrect one sends `wrongpass`)
  - Different agent versions (`v4.15.0` for the "modern" share, `v4.12.0` otherwise)
  - Agent group assignments (the only group sent is `default`)
- **Configurable delays** for connection and send operations
- **Detailed statistics** with response time analysis
- **CSV export** for further analysis
- **Graceful interruption** with Ctrl+C support

## Compilation

### Prerequisites

- CMake 3.12.4 or higher
- C++17 compatible compiler
- OpenSSL development libraries
- pthread support

### Build Instructions

It is a standalone CMake project, not part of the manager build:

```bash
cd tools/testing/enrollment-simulator

# Configure the build (Debug unless CMAKE_BUILD_TYPE is given; -DFSANITIZE=ON adds ASAN/UBSAN to Debug)
cmake -B build

# Build the project
cmake --build build
```

The executable `enrollment-simulator` will be created in the `build/` directory.

## Usage

### Basic Usage

```bash
./enrollment-simulator --host localhost --port 1515 --total 1000 --threads 4
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host HOST` | Target Wazuh server hostname or IPv4 address (resolved to IPv4 only) | localhost |
| `--port PORT` | Target port for wazuh-manager-authd | 1515 |
| `--password PASS` | Correct authentication password (optional) | none |
| `--threads N` | Number of concurrent threads | 4 |
| `--total N` | Total number of registrations to perform | 10000 |
| `--new-ratio RATIO` | Ratio of new agents (0.0-1.0) | 0.5 |
| `--incorrect-pass-ratio RATIO` | Ratio of incorrect passwords (0.0-1.0) | 0.01 |
| `--modern-version-ratio RATIO` | Ratio of modern version agents (0.0-1.0) | 0.05 |
| `--group-ratio RATIO` | Ratio of agents with group assignment (0.0-1.0) | 0.5 |
| `--connect-delay MS` | Delay before TLS handshake in milliseconds | 0 |
| `--send-delay MS` | Delay before sending request in milliseconds | 0 |
| `--log-file FILE` | Write output to file (and stdout) | - |
| `--csv-file FILE` | Export results to CSV file | - |
| `--help` | Show help message | - |

### Password Behavior

The `--password` option is optional. When it is omitted, requests drawn as "correct password" are
sent without an `OSSEC PASS:` field. The `--incorrect-pass-ratio` share still sends
`OSSEC PASS: wrongpass`, whether or not `--password` is given; set the ratio to `0` for a run with
no password at all. Without `--password`, a manager with `<use_password>yes</use_password>` (the
installed default) refuses every request.

Unrecognized options are ignored, and a malformed number aborts with an exception. A completed run
exits `0` whatever its success rate; read the statistics, not the exit code.

### Delay Ranges

Both `--connect-delay` and `--send-delay` support range specifications:
- Single value: `100` (fixed 100ms delay)
- Range: `100-500` (random delay between 100-500ms)

## Example Usage Scenarios

### Basic Load Test
```bash
./enrollment-simulator --host 192.168.1.100 --total 5000 --threads 8 \
  --password "$(sudo cat /var/wazuh-manager/etc/authd.pass)"
```

### High-Load with Delays
```bash
./enrollment-simulator \
  --host production-server \
  --total 10000 \
  --threads 16 \
  --connect-delay 50-200 \
  --send-delay 10-100 \
  --csv-file results.csv
```

### Error Scenario Testing
```bash
./enrollment-simulator \
  --host localhost \
  --total 1000 \
  --incorrect-pass-ratio 0.1 \
  --new-ratio 0.8 \
  --log-file error-test.log
```

## Output

### Console Output

The simulator provides progress updates (every 100 registrations) and comprehensive statistics:

```text
Resolved localhost to 127.0.0.1
Starting simulation with 4 threads...
Total registrations: 10000
Target server: localhost:1515
Connect delay: 0 ms
Send delay: 0 ms
Press Ctrl+C to stop early and see partial results
------------------------------------------------------------
  Progress: 2500 registrations completed...

============================================================
SIMULATION RESULTS
============================================================

Overall Statistics:
  Target registrations: 10000
  Completed registrations: 10000 (100.00% of target)
  Successful: 9950 (99.50%)
  Failed: 50 (0.50%)
  Total time: 45.23 seconds
  Throughput: 221.12 registrations/second

Response Time Statistics (ms):
  Min: 2.34
  Max: 156.78
  Mean: 18.45
  Median: 15.67
  Std Dev: 12.34

Statistics by Category:
------------------------------------------------------------
...
```

### CSV Output

When using `--csv-file`, detailed metrics are exported including:
- Overall performance statistics
- Response time analysis
- Category-based breakdowns (agent type, password correctness, version, groups)

## Signal Handling

- **Ctrl+C**: Gracefully stops the simulation and displays partial results
- **SIGPIPE**: Ignored to handle broken connections gracefully

## Performance Considerations

- The simulator resolves the target hostname once at startup to minimize DNS overhead
- One SSL context is created at startup and shared by every thread; each registration opens its own
  TCP connection and TLS session (no session reuse), with a 30 s send/receive timeout
- Registrations are split evenly across threads up front, and each thread runs its share back to
  back with no pacing other than the configured delays
- The random generator is a single instance shared by all threads; only the delay distribution is
  thread-local
- Memory usage scales linearly with the number of completed registrations

## Troubleshooting

### SSL Connection Issues
- Ensure wazuh-manager-authd is running and its legacy listener is enabled (`<auth><legacy_enrollment>`, or `<remote><legacy><enabled>` when it is unset)
- Check firewall settings for the target port
- Verify SSL certificate configuration (simulator uses `SSL_VERIFY_NONE` for testing)

### High Error Rates
- Check `/var/wazuh-manager/logs/wazuh-manager.log` (lines tagged `wazuh-manager-authd`) for error details
- Verify the correct password is configured
- Repeated names (`--new-ratio` below 1.0) re-register a name this run already enrolled, so they go through authd's duplicate-name policy (`<auth><force>`): depending on it they replace the earlier agent or are refused
- Ensure sufficient system resources on both client and server

### Performance Issues
- Monitor system resources (CPU, memory, network)
- Adjust thread count based on system capabilities
- Consider using delays to simulate realistic client behavior

## License

This tool is part of the Wazuh project and follows the same licensing terms.

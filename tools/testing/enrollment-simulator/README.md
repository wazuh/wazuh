# Enrollment Simulator

A performance testing tool for the Wazuh authentication daemon (`wazuh-authd`). This simulator generates concurrent SSL connections to test agent enrollment scenarios under various load conditions.

## Overview

The enrollment simulator creates multiple threads that simultaneously attempt to register agents with the Wazuh authentication daemon. It supports various agent configurations and provides detailed performance statistics including response times, success rates, and throughput metrics.

## Features

- **Multi-threaded simulation** with configurable thread count
- **SSL/TLS connections** to wazuh-authd
- **Configurable agent scenarios**:
  - New vs. repeated agent registrations
  - Correct vs. incorrect passwords
  - Different agent versions
  - Agent group assignments
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

```bash
cd tools/testing/enrollment-simulator

# Configure the build
cmake -B build

# Build the project
cmake --build build

The executable `enrollment-simulator` will be created in the `build/` directory.

## Usage

### Basic Usage

```bash
./enrollment-simulator --host localhost --port 1515 --total 1000 --threads 4
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--host HOST` | Target Wazuh server hostname or IP | localhost |
| `--port PORT` | Target port for wazuh-authd | 1515 |
| `--password PASS` | Correct authentication password | topsecret |
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

### Delay Ranges

Both `--connect-delay` and `--send-delay` support range specifications:
- Single value: `100` (fixed 100ms delay)
- Range: `100-500` (random delay between 100-500ms)

## Example Usage Scenarios

### Basic Load Test
```bash
./enrollment-simulator --host 192.168.1.100 --total 5000 --threads 8
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

The simulator provides real-time progress updates and comprehensive statistics:

```
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
- SSL contexts are reused across connections within each thread
- Random number generation is thread-local to avoid contention
- Memory usage scales linearly with the number of completed registrations

## Troubleshooting

### SSL Connection Issues
- Ensure wazuh-authd is running and accepting SSL connections
- Check firewall settings for the target port
- Verify SSL certificate configuration (simulator uses `SSL_VERIFY_NONE` for testing)

### High Error Rates
- Check wazuh-authd logs for error details
- Verify the correct password is configured
- Ensure sufficient system resources on both client and server

### Performance Issues
- Monitor system resources (CPU, memory, network)
- Adjust thread count based on system capabilities
- Consider using delays to simulate realistic client behavior

## License

This tool is part of the Wazuh project and follows the same licensing terms.

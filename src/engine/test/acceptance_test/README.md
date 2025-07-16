# Acceptance Tests for Wazuh-Engine

## Overview

The `acceptance` directory contains scripts to measure the performance of the Wazuh-Engine. The primary script, `acceptance_test.sh`, is used to send events to the Wazuh-Engine, capturing and plotting the performance metrics.

## Configuration

The main script used for these tests is `acceptance_test.sh`, which is configured through several environment variables to specify the conditions and parameters of the test.

### Test Configurations

- **General Settings**
  - `STATS_MONITOR_POLL_TIME_SECS`: Sampling time in seconds for monitoring stats.

- **Benchmark Settings**
  - `BT_TIME`: Duration in seconds for the test.
  - `BT_RATE`: Rate of events sent per second (0 for infinite).
  - `BT_INPUT`: Path to the log file used as input for the test.
  - `BT_OUTPUT`: Output file path; used to count the processed logs/events.

### Engine Specific Configurations
  - `ORCHESTRATOR_THREADS`: Threads that will be used by the engine's orchestrator.

## Usage

### Running the Test Script

To execute the acceptance tests run:

```bash
./acceptance_test.sh
```

This script will conduct tests according to the specified configurations and generate two types of files:
- A `.log` file recording the EPS (events per second) results.
- A `.csv` file containing detailed performance metrics such as memory usage, CPU utilization, and disk writes.

### Benchmark Tool

The script utilizes `utils/benchmark_tool.go` to send events:

```bash
go run utils/benchmark_tool.go -h
```

### Monitoring Tool

The `utils/monitor.py` script is used to monitor the process and gather metrics:

```bash
python3 utils/monitor.py -h
```


## Requirements

Ensure you have Python 3, Go, and the necessary permissions to execute scripts and access system logs and configurations.

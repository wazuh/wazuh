# Acceptance Tests for Wazuh-Engine and Wazuh-Analysisd

## Overview

The `acceptance` directory contains scripts to measure the performance of the Wazuh-Engine and Wazuh-Analysisd. The primary script, `acceptance_test.sh`, is used to send events to both Wazuh-Analysisd and Wazuh-Engine, capturing and comparing their performance metrics.

## Configuration

The main script used for these tests is `acceptance_test.sh`, which is configured through several environment variables to specify the conditions and parameters of the test.

### Test Configurations

- **General Settings**
  - `DO_TEST_ANALYSISD`: Set to `false` to skip tests for Analysisd.
  - `DO_TEST_ENGINE`: Set to `true` to enable tests for the Engine.
  - `STATS_MONITOR_POLL_TIME_SECS`: Sampling time in seconds for monitoring stats.

- **Benchmark Settings**
  - `BT_TIME`: Duration in seconds for the test.
  - `BT_RATE`: Rate of events sent per second (0 for infinite).
  - `BT_INPUT`: Path to the log file used as input for the test.
  - `BT_OUTPUT`: Output file path; used to count the processed logs/events.

### Engine Specific Configurations
  - `ENGINE_BUILD_ABSOLUTE_PATH`: Absolute path to the Engine's binary.
  - `ENGINE_N_THREADS`: Number of threads to use when launching Wazuh-Engine for the test.

### Analysisd Specific Configurations
  - Directories for configuration and ruleset files are specified to replace the existing ones temporarily during the test.

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

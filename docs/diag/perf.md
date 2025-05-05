# Benchmarking the Engine

This document describes the methodology used to benchmark the performance of the engine in a consistent and repeatable manner. The goal is to assess system behavior under varying loads and configurations while capturing detailed performance metrics.

The benchmarking process is designed to reflect real-world usage patterns by replaying logged event inputs and analyzing the system's throughput, resource usage, and internal processing characteristics. The results provide actionable insights for optimizing engine performance and tuning deployment configurations.

The benchmark workflow consists of the following key phases:

1. **Input Collection** – Prepares a set of event inputs based on real test cases, shuffled for variability.
2. **Warmup Phase** – Initializes the engine and ruleset with a small input subset to confirm correctness (excluded from metrics).
3. **Benchmark Phase** – Executes the core test while capturing performance metrics, with configurable parameters like EPS and thread counts.
4. **Teardown Phase** – Cleans up the test environment while monitoring the system under idle conditions.
5. **Monitoring** – Collects detailed OS-level statistics (CPU, memory, disk I/O) throughout all phases.
6. **Results** – Persists all relevant metrics, logs, and visualizations (e.g., flamegraphs, CSV reports).

## Setting up

Before running the benchmark, ensure your environment meets the following prerequisites.

### Prerequisites

- **Linux `perf` tool**

  Used for collecting low-level CPU performance data. [perf wiki](https://perfwiki.github.io/main/).

  **Ubuntu installation**
  ```bash
  sudo apt install linux-tools-common
  ```

- **Linux `pidstat` tool**
  Used for collecting OS metrics (memory, I/O and CPU usage).

  **Ubuntu installation**
  ```bash
  sudo apt install sysstat
  ```

- **`engine-bench` python package**

  A helper tool for orchestrating benchmark runs and collecting metrics.
  - [engine-bench](https://github.com/wazuh/wazuh/blob/main/src/engine/tools/engine-bench)

  ```bash
  pip install engine-bench
  ```

- **Sudo privileges**

  Required for running `perf` and accessing system-level metrics.

- **Compiling the Engine with the `perf` preset**

  The engine must be compiled using the perf build preset to enable accurate performance metrics.

  ```bash
  cmake --preset=perf
  cmake --build
  ```

### Parametrization

```bash
Usage: engine-bench [OPTIONS]

  Benchmark the Wazuh engine executable using perf.

Options:
  -e, --environment PATH  Path to the environment directory.  [required]
  -o, --output PATH       Path to the output directory for the benchmark
                          results.  [required]
  -h, --help              Show this message and exit.
```

## Execution

To execute the benchmark first we must create the environment and prepare the input logs:
```bash
WIP
```

Launching the benchmark:
```bash
engine-bench -e <path_to_environment> -o <output_directory>
```

### Examples
WIP

## Output

The benchmark generates the following outputs under the specified directory:
```bash
WIP
```

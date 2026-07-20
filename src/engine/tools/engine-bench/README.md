# Engine-Bench

`engine-bench` is a benchmarking tool designed to evaluate the performance of the Wazuh engine. It leverages `perf` for performance profiling and generates flame graphs to visualize the performance bottlenecks and hotspots in the engine.

## Usage
```bash
engine-bench --environment /path/to/environment --output /path/to/output
```
### Options

```bash
Usage: engine-bench [OPTIONS]

  Benchmark the Wazuh engine executable using perf.

Options:
  -e, --environment PATH  Path to the environment directory.  [required]
  -o, --output PATH       Path to the output directory for the benchmark
                          results.  [required]
  -h, --help              Show this message and exit.
```

## Features
- Performance Profiling: Uses perf to collect performance data for the Wazuh engine.
- Flame Graph Generation: Automatically generates flame graphs using [Brendan Gregg's FlameGraph](https://github.com/brendangregg/FlameGraph) scripts (stackcollapse-perf.pl and flamegraph.pl).
- Customizable Output: Allows specifying the output directory for benchmark results.

## Prerequisites
- perf must be installed and available on your system.
- The script requires sudo privileges to run.

### Installing perf
**Ubuntu**
```bash
sudo apt install linux-tools-common
```
- https://launchpad.net/ubuntu/jammy/+package/linux-tools-common

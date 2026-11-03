# Engine-Bench

`engine-bench` is a benchmarking tool designed to evaluate the performance of the Wazuh engine. It leverages `perf` for performance profiling and generates flame graphs to visualize the performance bottlenecks and hotspots in the engine.

## Installation

Requires Python 3.12 or newer (`pyproject.toml`). From `src/engine/`, after its unpublished dependencies:

```bash
pip install tools/api-communication
pip install test/engine-test-utils
pip install tools/engine-bench
```

## Usage
```bash
sudo engine-bench --environment /path/to/environment --output /path/to/output
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

The environment directory must hold the engine binary `wazuh-engine` and a `config.env`, as prepared by
`test/setupEnvironment.py` followed by the `init` of `engine-it` or `engine-helper-test` (see the
[test README](../../test/README.md)). `engine-bench` starts the engine with that configuration (its output in
`<environment>/logs/engine.log`), records it with `perf record -g` for 10 seconds, stops it, and writes
`perf.data`, `perf.script`, `perf.folded` and `flamegraph.svg` to the output directory (created if its parent
exists).

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

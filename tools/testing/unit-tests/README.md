# Unit Tests

Docker-based unit testing suite for Wazuh components with automated report generation.

## Overview

Runs Wazuh's complete unit test suite using Docker, including CMocka tests, RTR toolset, and CTest integration for Linux/Windows components.

## Prerequisites

- Docker with permission to run containers
- Access to `ghcr.io/wazuh/unit-tests:latest` image

## Usage

```bash
# Run all unit tests (default)
./unit-tests.sh

# Run with parallel compilation
./unit-tests.sh --jobs 4
```

## Options

| Option | Description |
|--------|-------------|
| `--build-image` | Build the Docker image and exit |
| `--results` | Generate markdown results from existing result-\*.txt files |
| `--clean` | Remove generated files (result-\*.txt and \*.log) |
| `--jobs N` | Number of parallel compilation jobs (default: 1) |
| `--help` | Show help message |

## Test Components

- **Linux Manager CMocka tests**: Core Wazuh manager functionality
- **Linux Agent CMocka tests**: Agent components for Linux
- **Windows Agent CMocka tests**: Agent components for Windows
- **RTR Components**: Data provider, DBsync, Rsync, Syscollector, FIM
- **CTest Integration**: Standardized test execution

## Output

Generates markdown report with test results and coverage statistics:

```markdown
## Linux Manager cmocka tests

|Test|Status|
|---|:-:|
|test_component_init|🟢|
|test_error_handling|🔴|

### Coverage
|Coverage type|Percentage|Result|
|---|---|---|
|Lines|85.4%|🟢|
```

## Examples

```bash
# Standard execution
./unit-tests.sh

# Fast compilation with 8 jobs
./unit-tests.sh --jobs 8

# Clean previous results
./unit-tests.sh --clean

# Re-generate report from existing results
./unit-tests.sh --results
```
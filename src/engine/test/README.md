# End-to-End Tests for Wazuh-Engine

This directory contains a comprehensive suite of end-to-end tests for the Wazuh-Engine project. These tests are designed to ensure the reliability and stability of the Wazuh-Engine across various components and operations.

## Test Categories

- **Acceptance Tests**: Located in the `acceptance/` directory. These tests focus on performance comparisons between Wazuh-Engine and Wazuh-Analysisd.
- **Integration Tests**: Located in the `integration/` directory. These tests cover the integration aspects of the Wazuh-Engine components.
- **Health Tests**: Located in the `health/` directory. These tests verify the expected versus actual outputs of the Wazuh-Engine and check the correctness of the Wazuh-Engine rulesets.
- **Helper Functions Tests**: Located in the `helpers/` directory. These tests validate the functionality of helper functions used within the assets.
- **Source Tests**: Located in the `source/` directory. These focus on the source components of the Wazuh-Engine. Note: These tests will be migrated to `../source/{component}/test/unit_test` and `../source/{component}/test/component_test` in the future.

## Environment Setup Script

The `setupEnvironment.py` script is used to configure the environment necessary for running the tests, ensuring that Wazuh-Engine operates in a controlled, sandboxed environment.

### Prerequisites

- **Python 3.8+**
- **pip3**
- **engine-suite**: This package includes several tools that facilitate the use of the Wazuh-Engine ecosystem, these tools are used by the tests and the user to interact with the api in a simple way.
- **api-communication**: This package facilitates communication with the Wazuh API, crucial for some components that interact directly with the Wazuh API.
### Installation

First, ensure that you have Python and pip installed on your system. Then, install the required Python packages by navigating to the root directory of the Wazuh repository and running the following commands:

```bash
pip3 install tools/api-communication
pip3 install tools/engine-suite
```

### Usage

To set up the test environment, use the following command syntax:

```bash
./setupEnvironment.py [-h] [-e ENVIRONMENT]
```

**Optional Arguments:**

- `-h, --help`: Show the help message and exit.
- `-e ENVIRONMENT, --environment ENVIRONMENT`: Specify the directory for the test environment.

**Example:**

```bash
./setupEnvironment.py -e /tmp/engine
```

This command sets up the testing environment in the `/tmp/engine` directory.

## Running Tests

To run tests, navigate to the respective test category directory and follow the specific instructions provided in the README.md of each directory. Ensure the environment is set up using `setupEnvironment.py` before running any tests to avoid conflicts and ensure accurate results.

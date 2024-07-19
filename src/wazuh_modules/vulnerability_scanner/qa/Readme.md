# QA Tests

This document is meant to describe the current component test behavior and the steps required for its maintenance.

## Efficacy test

### Description

The purpose of this test is to verify the scanner's accuracy when some specific inputs are applied. The results are verified by analyzing the logs written by the test tool.

The `test_data` folder is read in ascending order, and for each one of them, the corresponding inputs are sent. There is an output expected file that contains all the lines that should be found for those specific inputs. If the line isn't found after the timeout expires, the corresponding error message is printed. The test also verifies that the scan begins/ends properly, and that all the events are processed.

Consider also that folder `000` only verifies that the DB is properly decompressed, that's why it doesn't contain input files.

### How to add cases

When a new test is being added, these are the general steps to follow:
- Create a new folder, use the next available number
- Add `input_xxx.json` files that contain the sync/deltas messages that the vulnerability scanner test tool will process
- For each input, create an `expected_xxx.out` file. The logs in the array will be looked for in the test output. If the inputs only prepares the tests and no output is expected (for example, agent OS information), the file can contain an empty array.


## Policy change test

### Description

The purpose of this test is to verify the correct scanner behavior in different situations that involve configuration changes and/or different mocked DB data.

Each folder contains a sequence of arguments that will be used to run the test tool.


## Running local tests

To run the tests locally, run the tests from `src` folder. Include `--log-cli-level=DEBUG` at the end for verbose output.
There are two options related to the content:
- The feed will be provided without compression: store the content in `src/queue/feed`
- The feed will be decompressed during the test: store the compressed content at `src/tmp/`

A single test can be run with the environment variable `WAZUH_VD_TEST_FN_GLOB`, `WAZUH_VD_TEST_GLOB`, or `WAZUH_VD_TEST_FP_GLOB`.
Also, a folder called `qa_logs` to store the logs of each test can be created. Its location is passed with the environment variable `GITHUB_WORKSPACE`.

Examples:

- `python3 -m pytest  -vv wazuh_modules/vulnerability_scanner/qa --log-cli-level=DEBUG`
- `GITHUB_WORKSPACE=/workspaces/wazuh/ python3 -m pytest -vv wazuh_modules/vulnerability_scanner/qa --log-cli-level=DEBUG`
- `WAZUH_VD_TEST_FN_GLOB=001 GITHUB_WORKSPACE=/workspaces/wazuh/ python3 -m pytest  -vv wazuh_modules/vulnerability_scanner/qa/test_efficacy_log.py --log-cli-level=DEBUG`
- `python3 -m pytest -rA --md-report --md-report-verbose=1 --md-report-zeros empty --md-report-output md_report.md -vv wazuh_modules/vulnerability_scanner/qa --log-cli-level=DEBUG`
- `python3 -m pytest -rA --html=report.html --self-contained-html -vv wazuh_modules/vulnerability_scanner/qa/ --log-cli-level=DEBUG`

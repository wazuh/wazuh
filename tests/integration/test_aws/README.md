# AWS Integration

## Description

It is a _wodle based_ module that has a capability to pull logs from several AWS services.

## Tests directory structure

```bash
wazuh-qa/tests/integration/test_aws
├── conftest.py
├── data
│   ├── configuration_template
│   │   ├── basic_test_module
│   │   ├── discard_regex_test_module
│   │   ├── only_logs_after_test_module
│   │   ├── path_suffix_test_module
│   │   ├── path_test_module
│   │   ├── regions_test_module
│   │   └── remove_from_bucket_test_module
│   └── test_cases
│       ├── basic_test_module
│       ├── discard_regex_test_module
│       ├── only_logs_after_test_module
│       ├── path_suffix_test_module
│       ├── path_test_module
│       ├── regions_test_module
│       └── remove_from_bucket_test_module
├── README.MD
├── test_basic.py
├── test_discard_regex.py
├── test_only_logs_after.py
├── test_path.py
├── test_path_suffix.py
├── test_regions.py
└── test_remove_from_bucket.py
```

## Deps directory structure

```bash
wazuh-qa/deps/wazuh_testing/wazuh_testing/modules/aws
├── cli_utils.py
├── constants.py
├── data_generator.py
├── db_utils.py
├── event_monitor.py
├── __init__.py
└── s3_utils.py
```

## Requirements

- The only extra dependency is `boto3`
- The module will assume there are already buckets, log groups and an inspector assessment with test data in AWS.

## Configuration settings

- **credentials**
    Set the credentials at `$HOME/.aws/credentials` (being `HOME` the home directory of the user who runs the tests, more information [here](https://documentation.wazuh.com/current/amazon/services/prerequisites/credentials.html#profiles)) with the content:

```ini
[qa]
aws_access_key_id = <access-key-value>
aws_secret_access_key = <secret-key-value>
```

## Setting up a test environment

You will need a proper environment to run the integration tests. You can use any virtual machine you wish. If you have
one already, go to the [integration tests section](#integration-tests)

If you use [Vagrant](https://www.vagrantup.com/downloads.html)
or [VirtualBox](https://www.virtualbox.org/wiki/Downloads), it is important to install the `vbguest` plugin since some
tests modify the system date and there could be some synchronization issues.

This guide will cover the following platforms: [Linux](#linux).

You can run these tests on a manager or an agent. In case you are using an agent, please remember to register it and use
the correct version (Wazuh branch).

_We are skipping Wazuh installation steps. For further information,
check [Wazuh documentation](https://documentation.wazuh.com/current/installation-guide/index.html)._

### Linux

_We are using **Ubuntu 22.04** for this example:_

- Install **Wazuh**

- Install python tests dependencies:

    ```shell script
    # Install pip
    apt install python3-pip

    # Clone your `wazuh-qa` repository within your testing environment
    cd wazuh-qa

    # Install Python libraries
    python3 -m pip install -r requirements.txt

    # Install test dependecies
    python3 -m pip install deps/wazuh-testing
    ```


## Integration tests

**DISCLAIMER:** this guide assumes you have a proper testing environment. If you do not, please check
our [testing environment guide](#setting-up-a-test-environment).

### Pytest

We use [pytest](https://docs.pytest.org/en/latest/contents.html) to run our integrity tests. Pytest will recursively
look for the closest `conftest` to import all the variables and fixtures needed for every test. If something is lacking
from the closest one, it will look for the next one (if possible) until reaching the current directory. This means we
need to run every test from the following path, where the general _conftest_ is:

```shell script
cd wazuh-qa/tests/integration
```

To run any test, we just need to call `pytest` from `python3` using the following line:

```shell script
python3 -m pytest [options] [file_or_dir] [file_or_dir] [...]
```

**Options:**

- `v`: verbosity level (-v or -vv. Highly recommended to use -vv when tests are failing)
- `s`: shortcut for --capture=no. This will show the output in real time
- `x`: instantly exit after the first error. Very helpful when using a log truncate since it will keep the last failed
  result
- `k`: only run tests which match the given substring expression (-k EXPRESSION)
- `m`: only run tests matching given expression (-m MARKEXPR)
- `--tier`: only run tests with given tier (ex. --tier 2)
- `--html`: generates a HTML report for the test results. (ex. --html=report.html)
- `--default-timeout`: overwrites the default timeout (in seconds). This value is used to make a test fail if a
  condition is not met before the given time lapse. Some tests make use of this value and other has other fixed timeout
  that cannot be modified.

_Use `-h` to see the rest or check its [documentation](https://docs.pytest.org/en/latest/usage.html)._

Also, these integration tests are heavily based on [fixtures](https://docs.pytest.org/en/latest/fixture.html), so please
check its documentation for further information.

#### AWS integration tests example

```bash
# python3 -m pytest -vvx test_aws/ -k cloudtrail
=========================================================== test session starts ======================================================
platform linux -- Python 3.10.6, pytest-7.1.2, pluggy-1.0.0 -- /usr/bin/python3
cachedir: .pytest_cache
metadata: {'Python': '3.10.6', 'Platform': 'Linux-5.15.0-58-generic-x86_64-with-glibc2.35',
'Packages': {'pytest': '7.1.2', 'py': '1.10.0', 'pluggy': '1.0.0'},
'Plugins': {'metadata': '2.0.2', 'html': '3.1.1', 'testinfra': '5.0.0'}}
rootdir: /home/vagrant/qa/tests/integration, configfile: pytest.ini
plugins: metadata-2.0.2, html-3.1.1, testinfra-5.0.0
collected 15 items

test_aws/test_basic.py::test_defaults[cloudtrail_defaults] PASSED                                                               [  6%]
test_aws/test_discard_regex.py::test_discard_regex[cloudtrail_discard_regex] PASSED                                             [ 13%]
test_aws/test_only_logs_after.py::test_without_only_logs_after[cloudtrail_without_only_logs_after] PASSED                       [ 20%]
test_aws/test_only_logs_after.py::test_with_only_logs_after[cloudtrail_with_only_logs_after] PASSED                             [ 26%]
test_aws/test_only_logs_after.py::test_multiple_calls[cloudtrail_only_logs_after_multiple_calls] PASSED                         [ 33%]
test_aws/test_path.py::test_path[cloudtrail_path_with_data] PASSED                                                              [ 40%]
test_aws/test_path.py::test_path[cloudtrail_path_without_data] PASSED                                                           [ 46%]
test_aws/test_path.py::test_path[cloudtrail_inexistent_path] PASSED                                                             [ 53%]
test_aws/test_path_suffix.py::test_path_suffix[cloudtrail_path_suffix_with_data] PASSED                                         [ 60%]
test_aws/test_path_suffix.py::test_path_suffix[cloudtrail_path_suffix_without_data] PASSED                                      [ 66%]
test_aws/test_path_suffix.py::test_path_suffix[cloudtrail_inexistent_path_suffix] PASSED                                        [ 73%]
test_aws/test_regions.py::test_regions[cloudtrail_region_with_data] PASSED                                                      [ 80%]
test_aws/test_regions.py::test_regions[cloudtrail_regions_with_data] PASSED                                                     [ 86%]
test_aws/test_regions.py::test_regions[cloudtrail_inexistent_region] PASSED                                                     [ 93%]
test_aws/test_remove_from_bucket.py::test_remove_from_bucket[cloudtrail_remove_from_bucket] PASSED                              [100%]

=============================================== 15 passed, 2 warnings in 332.67s (0:05:32) ===========================================
```

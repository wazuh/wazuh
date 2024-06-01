# AWS Integration tests

## Description

It is a _wodle based_ module that tests the capabilities of the Wazuh AWS integration, pulling logs from different
buckets and services.

## Tests directory structure

```bash
wazuh/tests/integration/test_aws
├── data
│   ├── configuration_template
│   │   ├── basic_test_module
│   │   ├── custom_bucket_test_module
│   │   ├── discard_regex_test_module
│   │   ├── log_groups_test_module
│   │   ├── only_logs_after_test_module
│   │   ├── parser_test_module
│   │   ├── path_suffix_test_module
│   │   ├── path_test_module
│   │   ├── regions_test_module
│   │   └── remove_from_bucket_test_module
│   └── test_cases
│       ├── basic_test_module
│       ├── custom_bucket_test_module
│       ├── discard_regex_test_module
│       ├── log_groups_test_module
│       ├── only_logs_after_test_module
│       ├── parser_test_module
│       ├── path_suffix_test_module
│       ├── path_test_module
│       ├── regions_test_module
│       └── remove_from_bucket_test_module
├── __init__.py
├── README.md
├── conftest.py
├── test_basic.py
├── test_custom_bucket.py
├── test_discard_regex.py
├── test_log_groups.py
├── test_only_logs_after.py
├── test_path.py
├── test_path_suffix.py
├── test_regions.py
├── test_remove_from_bucket.py
└── utils.py
```

## Requirements

- [Proper testing environment](#setting-up-a-test-environment)

- [Wazuh](https://github.com/wazuh/qa-integration-framework) repository.

- [Testing framework](https://github.com/wazuh/qa-integration-framework) installed.

- An Inspector assessment with test data in AWS. The rest of the necessary resources are created in test execution time.

For a step-by-step example guide using linux go to the [test setup section](#linux)


## Configuration settings

- **Credentials**:
    Set the credentials at `$HOME/.aws/credentials` (being `HOME` the home directory of the user who runs the tests, 
 more information [here](https://documentation.wazuh.com/current/amazon/services/prerequisites/credentials.html#profiles) with the content:

```ini
[default]
aws_access_key_id = <access-key-value>
aws_secret_access_key = <secret-key-value>
```

The provided credentials must have the following set of minimum permissions defined in AWS:
```
    "s3:PutObject",
    "s3:PutObjectAcl",
    "s3:GetObject",
    "s3:GetObjectAcl",
    "s3:ListBucket",
    "s3:CreateBucket",
    "s3:DeleteObject",
    "s3:DeleteBucket",
    "s3:PutBucketNotification",
    "s3:GetBucketAcl"

    "ec2:CreateVpc",
    "ec2:CreateSubnet",
    "ec2:DescribeAvailabilityZones",
    "ec2:CreateRouteTable",
    "ec2:CreateRoute",
    "ec2:AssociateRouteTable",
    "ec2:ModifyVpcAttribute",
    "ec2:DeleteFlowLogs",
    "ec2:DeleteVpc",
    "ec2:DeleteRouteTable",
    "ec2:DeleteRoute",
    "ec2:CreateFlowLogs",
    "ec2:DescribeFlowLogs",
    "ec2:CreateTags"

   "logs:CreateLogStream",
    "logs:DeleteLogGroup",
    "logs:DescribeLogStreams",
    "logs:CreateLogGroup",
    "logs:GetLogEvents",
    "logs:DeleteLogStream",
    "logs:PutLogEvents",
    "logs:CreateLogDelivery",
    "logs:DeleteLogDelivery",
    "logs:PutResourcePolicy"

    "sqs:ReceiveMessage",
    "sqs:CreateQueue",
    "sqs:DeleteMessage",
    "sqs:DeleteQueue",
    "sqs:SetQueueAttributes",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl"

    "inspector:ListFindings",
    "inspector:DescribeFindings"
```

## Setting up a test environment

You will need a proper environment to run the integration tests. You can use Docker or any virtual machine. If you have
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

- Install Python tests dependencies:

    ```shell script
    # Install pip
    apt install python3-pip git -y

    # Clone `wazuh` repository within your testing environment
    git clone https://github.com/wazuh/wazuh.git

    # Clone the `qa-integration-framework` repository withing your testing environment
    git clone https://github.com/wazuh/qa-integration-framework.git
  
    # Install tests dependencies
    python3 -m pip install qa-integration-framework/
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
    cd wazuh/tests/integration/test_aws/
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
  condition is not met before the given timelapse. Some tests make use of this value and other has other fixed timeout
  that cannot be modified.

_Use `-h` to see the rest or check its [documentation](https://docs.pytest.org/en/latest/usage.html)._

Also, these integration tests are heavily based on [fixtures](https://docs.pytest.org/en/latest/fixture.html), so please
check its documentation for further information.

#### AWS integration tests example

```bash
#root@wazuh-master:/wazuh/tests/integration# pytest -x test_aws/ --disable-warnings
==================================== test session starts ====================================
platform linux -- Python 3.10.12, pytest-7.1.2, pluggy-1.2.0
rootdir: /wazuh/tests/integration, configfile: pytest.ini
plugins: testinfra-5.0.0, metadata-3.0.0, html-3.1.1
collected 195 items

test_aws/test_basic.py ................                                               [  8%]
test_aws/test_discard_regex.py ..............                                         [ 15%]
test_aws/test_log_groups.py ..                                                        [ 16%]
test_aws/test_only_logs_after.py .............................................x.      [ 40%]
test_aws/test_parser.py ..........................                                    [ 53%]
test_aws/test_path.py ..........................................                      [ 75%]
test_aws/test_path_suffix.py .........                                                [ 80%]
test_aws/test_regions.py ........................                                     [ 92%]
test_aws/test_remove_from_bucket.py ...sss.........                                   [100%]

============ 191 passed, 3 skipped, 1 xfailed, 7 warnings in 3723.08s (1:02:03) =============
```

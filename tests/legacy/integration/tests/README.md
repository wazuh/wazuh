# wazuh-qa

Wazuh - Quality assurance automation templates

## Setting up a test environment

You will need a proper environment to run the integration tests. You can use any virtual machine you wish. If you have
one already, go to the [integration tests section](#integration-tests)

If you use [Vagrant](https://www.vagrantup.com/downloads.html)
or [VirtualBox](https://www.virtualbox.org/wiki/Downloads), it is important to install the `vbguest` plugin since some
tests modify the system date and there could be some synchronization issues.

This guide will cover the following platforms: [Linux](#linux), [Windows](#windows) and [MacOS](#macos).

You can run these tests on a manager or an agent. In case you are using an agent, please remember to register it and use
the correct version (Wazuh branch).

_We are skipping Wazuh installation steps. For further information,
check [Wazuh documentation](https://documentation.wazuh.com/3.11/installation-guide/index.html)._

### Linux

_We are using **CentOS** for this example:_

- Install **Wazuh**

- Disable firewall (only for **CentOS**)

```shell script
systemctl stop firewalld
systemctl disable firewalld
```

- Install Python and its dependencies

```shell script
# Install dependencies
yum install make gcc policycoreutils-python automake autoconf libtool epel-release git which sudo wget -y

# Install development dependencies for jq library
yum groupinstall "Development Tools" -y

# Install Python3
yum install python36 python36-pip python36-devel -y

# Install Python libraries
pip3 install pytest freezegun jq jsonschema pyyaml==5.3 psutil distro pandas==0.25.3 pytest-html==2.0.1 numpydoc==0.9.2
```

- Add some internal options and restart

```shell script
# Enable debug 2
echo 'syscheck.debug=2' >> $wazuh_path/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time (only for agents)
sed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /var/ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> $wazuh_path/etc/local_internal_options.conf

# Restart Wazuh
/var/ossec/bin/wazuh-control restart
```

### Windows

- Install **Wazuh**

- Download and install [Python](https://www.python.org/downloads/windows/)

- Download and install [chocolatey](https://chocolatey.org/docs/installation) to be able to install `jq` using the
  terminal.

- Install `jq`:

```shell script
choco install jq
```

- Install Python dependencies

```shell script
pip install pytest freezegun jsonschema pyyaml==5.4 psutil paramiko distro pywin32 pypiwin32 wmi pandas==0.25.3 pytest-html==2.0.1 numpydoc==0.9.2
```

- Change `time-reconnect` from `C:\Program Files (x86)\ossec-agent\ossec.conf`

```xml
<time-reconnect>99999999999</time-reconnect>
```

- Add some internal options

```shell script
# Enable debug 2
echo 'syscheck.debug=2' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"

# Disable log rotation
echo 'monitord.rotate_log=0' >> "C:\Program Files (x86)\ossec-agent\local_internal_options.conf"
```

- Restart **Wazuh** using the GUI

### MacOS

- Install **Wazuh**

- Install Python and its dependencies

```shell script
# Install Python
brew install python3

# Install dependencies
brew install autoconf automake libtool

# Install Python libraries
pip3 install pytest freezegun jq jsonschema pyyaml==5.4 psutil paramiko distro pandas==0.25.3 pytest-html==2.0.1 numpydoc==0.9.2
```

- Add some internal options and restart

```shell script

# Enable debug 2
echo 'syscheck.debug=2' >> /Library/Ossec/etc/local_internal_options.conf

# Avoid agent disconnections when travelling in time
brew install gnu-sed
gsed -i "s:<time-reconnect>60</time-reconnect>:<time-reconnect>99999999999</time-reconnect>:g" /Library/Ossec/etc/ossec.conf

# Disable log rotation
echo 'monitord.rotate_log=0' >> /Library/Ossec/etc/local_internal_options.conf

# Restart Wazuh
/Library/Ossec/bin/wazuh-control restart
```

-----------

Finally, copy your `wazuh-qa` repository within your testing environment and you are set.

## Integration tests

**DISCLAIMER:** this guide assumes you have a proper testing environment. If you do not, please check
our [testing environment guide](#setting-up-a-test-environment).

Our newest integration tests are located in `wazuh-qa/tests/integration/`. They are organized by capabilities:

- _test_active_response_
- _test_agentd_
- _test_analysisd_
- _test_api_
- _test_authd_
- _test_aws_
- _test_enrollment_
- _test_fim_
- _test_gcloud_
- _test_logtest_
- _test_remoted_
- _test_rids_
- _test_rootcheck_
- _test_vulnerability_detector_
- _test_wazuh_db_
- _test_wpk_

Every group will have the following structure:

```bash
├── test_<capability>
│   ├── conftest.py (optional)
│   ├── test_<functionality>
│   │   ├── data
│   │   │   ├── <wazuh_conf>.yaml
│   │   │   └── <wazuh_conf>.yaml
│   │   ├── test_<module>.py
│   │   ├── test_<module>.py
│   │   └── test_<module>.py
│   ├── test_<functionality>
│   │   ├── data
│   │   │   └── <wazuh_conf>.yaml
│   │   ├── test_<module>.py
│   │   ├── test_<module>.py
│   │   ├── <auxiliary_module>.py (optional)
└── └── └── <script> (optional)
```

FIM test structure example:

```bash
├── test_fim
│   ├── conftest.py
.
.
.
│   ├── test_basic_usage
│   │   ├── data
│   │   │   ├── wazuh_conf_disabled.yaml
│   │   │   └── wazuh_conf.yaml
│   │   ├── test_basic_disabled.py
│   │   ├── test_basic_usage_baseline_generation.py
│   │   ├── test_basic_usage_changes.py
│   │   ├── test_basic_usage_create_rt_wd.py
│   │   ├── test_basic_usage_create_scheduled.py
│   │   ├── test_basic_usage_delete_folder.py
│   │   ├── test_basic_usage_entries_match_path_count.py
│   │   ├── test_basic_usage_move_dir.py
│   │   ├── test_basic_usage_move_file.py
│   │   ├── test_basic_usage_rename.py
│   │   └── test_basic_usage_starting_agent.py
.
.
.
│   ├── test_skip
│   │   ├── data
│   │   │   ├── configure_nfs.sh
│   │   │   ├── proc.py
│   │   │   ├── remove_nfs.sh
│   │   │   └── wazuh_conf.yaml
│   │   └── test_skip.py
│   ├── test_windows_audit_interval
│   │   ├── data
│   │   │   └── wazuh_conf.yaml
│   │   ├── manage_acl.py
│   │   └── test_windows_audit_interval.py
.
.
.
```

#### conftest

Every group could have its own `conftest` if it needed some specific configurations. For reference, please
check [pytest](#pytest) section below.

#### data

Folder with the configuration yaml's to create the testing environment. These yaml's have the `ossec.conf` that will be
applied to each module. This is a sample yaml used for `FIM`:

```yaml
---
# sample configuration
- tags:
  - sample_tag
  apply_to_modules:
  - sample_module
  sections:
  - section: syscheck
    elements:
    - disabled:
      value: 'no'
    - directories:
      value: '/sample_directory'
      attributes:
      - check_all: 'yes'
    - nodiff:
      value: '/sample_directory/nodiff_file'
```

- **tags**: Informative tag that could be used to filter out within test functions for the same module.
- **apply_to_modules**: Module/s that will load this configuration.
- **section**: Section that will be modified within `<ossec_config`.
- **elements**: Elements that will be written within the given section.
    - disabled: `<disabled>no</disabled>`
    - directories: `<directories check_all="yes">/sample_directory</directories>`
    - nodiff: `<nodiff>/sample_directory/nodiff_file</nodiff>`

We can use `wildcards` as well to parametrize values or attributes. For example, if we add a new attribute into the
previous configuration called `FIM_MODE` and we set this wildcard to `''`, `realtime="yes"` and `whodata="yes"`, it will
generate **three** different configurations. One for each _WILDCARD_ value.

#### test_module

This will be our python module with all the needed code to test everything.

### Dependencies

To run them, we need to install all these Python dependencies:

```shell script
pip3 install distro freezegun jq jsonschema psutil pytest pyyaml==5.3 pandas==0.25.3 pytest-html==2.0.1 numpydoc==0.9.2
```

_**NOTE:** `jq` library can only be installed with `pip` on **Linux**_

### Wazuh-Testing package

We have a Python package at `wazuh-qa/deps/` with all the tools needed to run these tests. From file monitoring classes
to callbacks or functions to create the test environment. Without installing this package, we cannot run these tests. It
has the following structure:

```bash
wazuh_testing
    ├── setup.py
    └── wazuh_testing
        ├── __init__.py
        ├── analysis.py
        ├── cluster.py
        ├── data
        │   ├── event_analysis_schema.json
        │   ├── mitre_event.json
        │   ├── state_integrity_analysis_schema.json
        │   ├── syscheck_event.json
        │   └── syscheck_event_windows.json
        ├── fim.py
        ├── gcloud.py
        ├── mitre.py
        ├── tools
        │   ├── __init__.py
        │   ├── configuration.py
        │   ├── file.py
        │   ├── monitoring.py
        │   ├── services.py
        │   ├── system.py
        │   └── time.py
        └── wazuh_db.py
```

#### setup.py

Python module with the needed code to install this package into our Python interpreter.

#### wazuh_testing

##### Python modules

These are _analysis.py_, _fim.py_, _mitre.py_ and _wazuh_db.py_. They have very specific tools needed for each
capability.

##### data

Folder with all the json schemas. One capability could have more than one schema depending on the platform.

##### tools

Folder with all the general tools that could be used in every test. They are grouped by:

- **Init**: `__init__` file with the common information between all these modules (paths set in execution time).

- **Configuration**:  functions to configure our environment (rewrite `ossec.conf`, load it, change metadata...)

- **File**: functions to work with files.

- **Monitoring**: everything related to monitoring a file.

- **Services**: from controlling Wazuh services, daemons and socket to common processes.

- **Time**:  classes and functions to 'travel in time' (needed for scheduled monitoring) and manage dates.

To install it:

```shell script
cd wazuh-qa/deps/wazuh_testing
pip3 install .
```

_**NOTE:** It is important to reinstall this package every time we modify anything
from `wazuh-qa/packages/wazuh_testing`_

```shell script
cd wazuh-qa/deps/wazuh_testing
pip3 uninstall -y wazuh_testing && pip3 install .
```

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
- `m`: only run tests matching given expression (-m MARKEXPR)
- `--tier`: only run tests with given tier (ex. --tier=2)
- `--html`: generates a HTML report for the test results. (ex. --html=report.html)
- `--default-timeout`: overwrites the default timeout (in seconds). This value is used to make a test fail if a
  condition is not met before the given time lapse. Some tests make use of this value and other has other fixed timeout
  that cannot be modified.
- `--fim_mode`: Specify the mode of execution of the FIM tests. (ex. --fim_mode="scheduled"). To run the test in
  realtime and whodata the option must be specified twice: --fim_mode="realtime" --fim_mode="whodata". If the option is
  not specified, the test will run using scheduled, whodata and realtime.
- `--wpk_version`: Specify the WPK package version used to upgrade on WPK tests. (ex. --wpk_version=v4.2.0). Note: This
  field is required to execute any WPK test and the WPK package must be previously created in
  the [repository](packages-dev.wazuh.com/trash/wpk/).
- `--wpk_package_path`: Specify the WPK package path used to upgrade on WPK tests. (ex. --wpk_package_path='packages-dev.wazuh.com/trash/wpk/').
   This field is required to execute any WPK test.
- `--save-file`: Specify the files of execution of the tests that you need to download. (ex. --save-file=archives.json).
   If the file does not exist while the test was executed,  the test will run without problems but not save this file in the report.

_Use `-h` to see the rest or check its [documentation](https://docs.pytest.org/en/latest/usage.html)._

Also, these integration tests are heavily based on [fixtures](https://docs.pytest.org/en/latest/fixture.html), so please
check its documentation for further information.

#### FIM integration tests examples

```shell script
python3 -m pytest -vvx test_fim/test_basic_usage/test_basic_usage_create_scheduled.py

========================================== test session starts ==========================================
platform linux -- Python 3.6.8, pytest-5.3.4, py-1.8.1, pluggy-0.13.1 -- /bin/python3
cachedir: .pytest_cache
rootdir: /vagrant/wazuh-qa/test_wazuh, inifile: pytest.ini
collected 12 items

test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file-regular-Sample content-checkers0-tags_to_apply0-/testdir1] PASSED [  8%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file-regular-Sample content-checkers0-tags_to_apply0-/testdir2] PASSED [ 16%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file2-regular-Sample content-checkers1-tags_to_apply1-/testdir1] PASSED [ 25%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file2-regular-Sample content-checkers1-tags_to_apply1-/testdir2] PASSED [ 33%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-socketfile-socket--checkers2-tags_to_apply2-/testdir1] PASSED [ 41%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-socketfile-socket--checkers2-tags_to_apply2-/testdir2] PASSED [ 50%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file3-regular-Sample content-checkers3-tags_to_apply3-/testdir1] PASSED [ 58%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file3-regular-Sample content-checkers3-tags_to_apply3-/testdir2] PASSED [ 66%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-fifofile-fifo--checkers4-tags_to_apply4-/testdir1] PASSED [ 75%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-fifofile-fifo--checkers4-tags_to_apply4-/testdir2] PASSED [ 83%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file4-regular--checkers5-tags_to_apply5-/testdir1] PASSED [ 91%]
test_fim/test_basic_usage/test_basic_usage_create_scheduled.py::test_create_file_scheduled[get_configuration0-file4-regular--checkers5-tags_to_apply5-/testdir2] PASSED [100%]

===================================== 12 passed in 60.38s (0:01:00) =====================================

```

```shell script
python3 -m pytest test_fim/test_report_changes/

=============================== test session starts ===============================
platform linux -- Python 3.6.8, pytest-5.3.4, py-1.8.1, pluggy-0.13.1
rootdir: /vagrant/wazuh-qa/test_wazuh, inifile: pytest.ini
collected 12 items

test_fim/test_report_changes/test_report_changes_and_diff.py ......         [ 50%]
test_fim/test_report_changes/test_report_deleted_diff.py ......             [100%]

========================= 12 passed in 212.23s (0:03:32) ==========================
```

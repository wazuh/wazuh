# Test execution

## Unit tests

### Core components

#### Requirements:
1. Compiling tools (GCC and/or mingw)
2. CMake (version 3.10 or higher)
3. Wine (For executing winagent tests)
4. CMocka (C Unit Testing Framework)

Additional dependencies can be installed on Ubuntu by running the following commands.
```
sudo apt-get update -y
sudo apt-get install -y gcc-mingw-w64 make python3 gcc g++ cmake libc6-dev curl policycoreutils automake autoconf libtool libssl-dev lcov
```

To install the additional dependencies on macOS run the following commands.
```
$ /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
$ brew install cmake
$ brew install cmocka
$ brew install lcov
```

#### Compile Wazuh
In order to run unit tests on a specific wazuh target, the project needs to be built with the `TEST` option as shown below:
```
make TARGET=server|agent|winagent TEST=1
```

#### Compile and run unit tests for Linux targets
In order to run unit tests for either the Wazuh server or Linux agents, these need to be built using [CMake](#installing-cmake) version 3.10 or higher and [cmocka](#installing-cmocka).

Navigate into `wazuh/src/unit_tests` and run the following commands:
```
mkdir build
cd build
cmake -DTARGET=server|agent ..
make
```
Notice that when running the cmake command we need to specify the target on which we will run the unit tests, this target needs to match the wazuh target used for compilation and wazuh needs to be previously compiled.

There are several ways to run unit tests:

In order to run all unit tests and get a global result for all of them you can run the `ctest` command inside the `build` directory. CTest will run all available tests and display their results on the console. If more details on the tests are required, you can inspect the `LastTest.log` located inside `build/Testing/Temporary` after running this command.

You can get a coverage report from the unit tests run by running `make coverage` inside the `build` directory. Tests will be run and if they all pass a `coverage-report` directory will be created with an html report.

In case you need to run a specific test, navigate into the subdirectory where the test resides and run it as you would any other Linux binary. As an example, if you want to run tests on `create_db.c`
```
cd syscheckd
./test_create_db
```
The output of the test will be written directly into the console.

#### Compile and run unit tests for Windows agent
Similarly to compiling unit tests for server or Linux agent configurations, [CMake](#installing-cmake) 3.10 or higher and [cmocka](#installing-cmocka) are required, as well as a 32 bit [wine installation](#installing-wine) in order to run the tests.

Navigate into `wazuh/src/unit_tests` and run the following commands:
```
mkdir build
cd build
cmake -DTARGET=winagent -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake ..
make
```
Just as when compiling server and Linux agent unit tests, the winagent target for Wazuh must be compiled previously.

The `CMAKE_TOOLCHAIN_FILE` option is added so crosscompiling of the unit tests can be properly configured by cmake.

There are several ways to run the tests:

In order to run all unit tests and get a global result for all of them you can run the `ctest` command inside the `build` directory. CTest will run all available tests by using wine and display their results on the console. If more details on the tests are required, you can inspect the `LastTest.log` located inside `build/Testing/Temporary` after running this command.

You can get a coverage report from the unit tests run by running `make coverage` inside the `build` directory. Tests will be run and if they all pass a `coverage-report` directory will be created with an html report.

In case you need to run a specific test, navigate into the subdirectory where the test resides and run it by using wine. As an example, if you want to run tests on `create_db.c`
```
cd syscheckd
wine test_create_db.exe
```
The output of the test will be written directly into the console.

#### Compile and run unit tests for macOS agent
Similarly to compiling unit tests for server or Linux agent configurations, [CMake](#installing-cmake) 3.10 or higher and [cmocka](#installing-cmocka) are required.

Navigate into `wazuh/src/unit_tests` and run the following commands:
```
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
mkdir build
cd build
cmake -DTARGET=agent ..
make
```
The agent target for Wazuh must be compiled previously. The tests are run in the same way as Linux systems.

If installing cmake using `apt-get` or `yum` yields a version lower the 3.10, remove it and run these commands to install from sources.

```
mkdir ~/temp
cd ~/temp
wget https://cmake.org/files/v3.17/cmake-3.17.0-rc1.tar.gz
tar -xzvf cmake-3.17.0-rc1.tar.gz
cd cmake-3.17.0-rc1/
./bootstrap
make
sudo make install
```

The cmocka unit tests framework is required in order to compile and run the Wazuh unit tests suite. For server and Linux agent tests, a binary installation of cmocka using a package manager is enough. If you want to run the Windows agent tests, you will need to build cmocka using the MinGW compiler.

1. Clone cmocka repository:
```
git clone https://git.cryptomilk.org/projects/cmocka.git
```

2. Checkout the `stable-1.1` branch

3. Modify `DefineOptions.cmake` file and set `BUILD_SHARED_LIBS` to `OFF`

4. Build CMocka by running the following commands inside the repository directory:
```
mkdir build
cd build
cmake -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```

If you need to build cmocka for the Linux targets, keep `BUILD_SHARED_LIBS` as `ON` and run the following commands
```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo make install
```
If you need to rebuild cmocka, remember to remove all files from the `build` directory first.

#### Installing wine
On Ubuntu, run the following commands:
```
# Add 32 bit architecture
sudo dpkg --add-architecture i386

# Add key
wget -qO - https://dl.winehq.org/wine-builds/winehq.key | sudo apt-key add -

###  Add repository (Ubuntu 19.10)
sudo apt-add-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ eoan main'

###  Add repository (Ubuntu 18.04)
sudo apt-add-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ bionic main'
sudo add-apt-repository ppa:cybermax-dexter/sdl2-backport


###  Add repository (Ubuntu 16.04)
sudo apt-add-repository 'deb https://dl.winehq.org/wine-builds/ubuntu/ xenial main'

# Install
sudo apt update
sudo apt install --install-recommends winehq-stable

### If unmet dependencies error, use aptitude
sudo apt install aptitude
sudo aptitude install winehq-stable

# Check version
wine --version

# Link wine binary
sudo ln -s /opt/wine-stable/bin/wine /usr/bin/
```

Commands above have been taken from the following guide: https://tecadmin.net/install-wine-on-ubuntu/
If you need to run the tests on a CentOS 7 machine, you can follow these instructions in order to build a 32 bit wine: https://www.systutorials.com/239913/install-32-bit-wine-1-8-centos-7/

After installing wine, the `WINEPATH` and `WINEARCH` variables need to be created in order for it to know it should run on 32 bit mode and find all required dlls for the tests. On an Ubuntu system, the following commands need to be executed and/or added into the user's `.bashrc` file.
```
export WINEPATH="/usr/i686-w64-mingw32/lib;/usr/lib/gcc/i686-w64-mingw32/13-posix;/path/to/wazuh/src;/path/to/wazuh/src/build/bin"
export WINEARCH=win32
```
If wine complains about being a 64 bit installation, remove/rename the directory `~/.wine` and run it again.

### API - Framework

#### Set up Python environment

Ensure the correct Python version is installed.  

The required version is defined in:

```text
.github/workflows/.python-version-it
```

Optionally, create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install -r framework/requirements-dev.txt
```

#### Tests execution

- For API tests

```bash
python -m pytest api/api
```

- For framework

```
python -m pytest framework
```

## Integration tests
### Core components

#### Set up Python environment

Ensure the correct Python version is installed.  

The required version is defined in:

```text
.github/workflows/.python-version-it
```

Optionally, create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install --upgrade pip
```

---

#### Install Wazuh

Install the Wazuh version untder testing, either from sources or from packages


#### Install the integration test framework

Determine the appropriate branch of the QA integration framework and install it:

```
git clone -b "$QA_BRANCH" --single-branch https://github.com/wazuh/qa-integration-framework.git
sudo pip install qa-integration-framework/
rm -rf qa-integration-framework/
```

---

#### Run the tests

Move to the integration tests directory:

```bash
cd tests/integration

python -m pytest \
  --tier <TIER> \
  <TEST FOLDER>/ \
  --html=results.html \
  --self-contained-html
```

---

The test execution generates an HTML report:

```text
tests/integration/results.html
```
### API

An integration test is used to check that the behavior of the different application modules is the expected one when 
they are integrated. In other words, the integration tests check the correct interaction between the application 
components.

The API integration tests are used to verify that the API is working properly in a complete Wazuh environment.
This environment is built using [`docker`](https://www.docker.com/).

The `wazuh/api/test/integration` directory contains all the API integration tests files and directories used for the
environment deployment.


#### Set up Python environment

Ensure the correct Python version is installed.  

The required version is defined in:

```text
.github/workflows/.python-version-it
```

Optionally, create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate
pip install -r framework/requirements-dev.txt
```

---

#### Integration tests files

The API integration tests files use the [`tavern`](https://tavern.readthedocs.io/en/latest/) framework. Tavern is
a [`pytest`](https://docs.pytest.org/en/7.1.x/) based API testing framework for HTTP, MQTT, or other protocols. These
files are written in the `yaml` language and their names can follow the following formats:

`test_{module}_endpoints.tavern.yaml` or `test_rbac_{rbac_mode}_{module}_endpoints.tavern.yaml`

where `module` is the module which the endpoints tested belong; and `rbac_mode` is the RBAC mode (white or black) used 
for the test (see [RBAC API integration tests](#RBAC-API-integration-tests)).

#### Docker environment

The Wazuh environment used to perform the API integration tests is built using `docker`.

This environment is composed of **12 docker containers**. These containers have the following components installed: 3
Wazuh managers, that compose a Wazuh cluster (1 master, 2 workers); 4 Wazuh agents with the same version as the managers
forming the cluster; 4 Wazuh agents with version 4.14.1 (old); and 1 HAProxy load balancer.

The Wazuh version used for the managers and non-old agents is the one specified by the branch used to perform the API
integration tests.

The `docker-compose.yml` file used to deploy the environment is at `wazuh/api/test/integration/env`. The `Dockerfile`,
`entrypoint.sh`, and other configuration files can be found in the `base` directory.

We also use specific **configurations and health checks depending on the test executed**. These configurations can be
found at the `configurations` directory. Python scripts commonly used by some of these health checks and files are
located in the `tools` directory.

Apart from this setup, we simulate 2 disconnected and 2 never-connected agents.

#### How is the environment deployed?

The environment deployment is done automatically when performing an API integration test. The tests are executed
with `pytest <test_name>`.

The `conftest.py` file is the one in charge of deploying the API integration tests environment. When a test is
performed, the `api_test` function is also executed. This function is responsible for setting up the environment and
cleaning temporary folders, stopping and removing containers; and saving log and environment status, once the test has 
finished. The execution of `api_test` is done automatically thanks to the `pytest.fixture` decorator.

In the `conftest.py` file, we can also find functions used to make the HTML report,
configure [RBAC](#RBAC-API-integration-tests), etc.

The environment is brought up automatically when running an API integration test. As seen in the table, the environment runs in **cluster** mode and tests are executed with `pytest`:

| Command                          | Environment                                          |  
|----------------------------------|------------------------------------------------------|
| `pytest TEST_NAME`               | Wazuh cluster environment                            |  


Talking about [RBAC API integration tests](#RBAC-API-integration-tests), they don't have any marks, so there is no need
to specify one when running them. If a mark is specified, no tests will be run due to the filters. In other words,
**RBAC tests are always going to be performed in the default cluster setup**.

#### RBAC API integration tests

As said in previous sections, some test names follow the structure
`test_rbac_{rbac_mode}_{module}_endpoints.tavern.yaml`.

These tests are used to check the proper functioning of a Wazuh environment with RBAC configurations. The `conftest.py`
file includes functions in charge of changing the RBAC mode and creating the specified RBAC resources for the test in
execution. The `env/configurations/rbac` directory includes all the specific configurations for each RBAC API 
integration test, for both **white** and **black** modes.

#### Tests execution

To perform a Wazuh API integration test, we need a specific `python3` environment. This python environment includes the 
following dependencies:

```python
pytest==5.4.3
requests==2.23.0
pyaml==21.10.1
tavern==1.0.0
pykwalify==1.7.0
pytest-html==2.1.1
```

The `docker-compose` version needed is **1.28.0 or newer**. **It cannot be 2.X.Y** as it includes breaking changes that
will make the generation of our API integration test environment fail.

Once these requirements are satisfied, we can perform the API integration tests:

```text
$ python3 -m pytest test_agent_GET_endpoints.tavern.yaml --disable-warnings
========================================== test session starts ===========================================
platform linux -- Python 3.9.9, pytest-5.4.3, py-1.11.0, pluggy-0.13.1
rootdir: /home/user/git/wazuh/api/test/integration, inifile: pytest.ini
plugins: html-2.1.1, metadata-2.0.1, tavern-1.0.0
collected 92 items                                                                                       

test_agent_GET_endpoints.tavern.yaml ............................................................. [ 66%]
...............................                                                                    [100%]

============================== 92 passed, 98 warnings in 217.61s (0:03:37) ===============================
```

```text
API integration tests

optional arguments:
  --build-managers-only            
                  Recreates only the managers' image once the AIT test environment is built.
  --nobuild
                  Prevents rebuilding the environment when running tests once the images are already created.
  --disable-warnings 
                  Disables warnings during test execution.
```

We can also use the `wazuh/api/test/integration/run_tests.py` script. This script includes the possibility to collect a 
group of tests to be passed. Script arguments:

```text
$ python3 run_tests.py -h
usage: run_tests.py [options]

API integration tests

optional arguments:
  -h, --help            show this help message and exit
  -l TEST_LIST, --list TEST_LIST
                        Specify a list of tests separated by a comma.
  -e, --exclude         Run every test excluding the already saved in the RESULTS_FOLDER.
  -r, --results         Get result summary from the already run tests.
  -k KEYWORD, --keyword KEYWORD
                        Specify the keyword to filter tests out. Default None.
  -R {both,yes,no}, --rbac {both,yes,no}
                        Specify what to do with RBAC tests. Run everything, only RBAC ones or no RBAC. Default "both".
  -i ITERATIONS, --iterations ITERATIONS
                        Specify how many times will every test be run. Default 1.
```

The `run_test.py` script does not show the tests' full output. The full reports are saved 
at `wazuh/api/test/integration/_test_results`. Containers' logs (`ossec.log`, `api.log` and `cluster.log`) are stored 
at `_test_results/logs`. Reports in HTML format are also generated and can be found at `_test_results/html_reports`.


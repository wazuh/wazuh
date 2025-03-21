# Build from Sources

## wazuh-server: Engine

### Prerequisites for building the engine

- [git](https://git-scm.com) 2.17 or higher
- [GCC](https://gcc.gnu.org) 11.4 or higher
- [CMake](https://cmake.org/download/) 3.30 or higher
- [VCPKG](https://vcpkg.io) 2021.05 or higher

#### Install Dependencies

***DEB-based systems***
```bash
# Install dependencies
sudo apt install curl zip unzip tar -y
sudo apt install build-essential -y
```

***RPM-based systems***
```bash
# Install dependencies
sudo yum install curl zip unzip tar -y
sudo yum groupinstall "Development Tools" -y
```

#### Install CMake 3.30

```bash
sudo su
# Install CMake 3.30
cd $HOME
wget https://github.com/Kitware/CMake/releases/download/v3.30.4/cmake-3.30.4-linux-x86_64.sh
chmod +x cmake-3.30.4-linux-x86_64.sh
mkdir -p /opt/cmake
/tmp/cmake-3.30.4-linux-x86_64.sh --prefix=/opt/cmake --skip-license
ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake
ln -s /opt/cmake/bin/ctest /usr/local/bin/ctest
```

#### Install VCPKG
```bash
# Install VCPKG
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
./bootstrap-vcpkg.sh
export VCPKG_ROOT=$(pwd)
export PATH=$VCPKG_ROOT:$PATH
echo "export VCPKG_ROOT=$(pwd)" >> ~/.bashrc
echo "export PATH=$VCPKG_ROOT:$PATH" >> ~/.bashrc
```

### Building the engine

```bash
git clone --recurse-submodules https://github.com/wazuh/wazuh.git
cd wazuh/src/engine
cmake --preset=relwithdebinfo
cmake --build build -j$(nproc)
```

The wazuh-engine binary will be generated in `src/engine/build/main`.

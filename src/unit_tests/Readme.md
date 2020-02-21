# Unit Tests Execution instructions

## Requeriments:
1. Compiling tools (GCC and mingw)
2. CMake (version 3.10 or higher)
3. Wine (For executing winagent tests)
4. CMocka (C Unit Testing Framework)


## Install Instructions (Ubuntu 16.10)

1. Install dependencies:
    ```
    sudo apt-get update -y
    sudo apt-get install -y gcc-mingw-w64 nsis make python gcc g++ cmake libc6-dev curl policycoreutils automake autoconf libtool libssl-dev lcov
    ```

2. In case `cmake --version < 3.10` remove from apt and install from sources:
    ```
    mkdir ~/temp
    cd ~/temp
    wget https://cmake.org/files/v3.17/cmake-3.17.0-rc1.tar.gz
    tar -xzvf cmake-3.17.0-rc1.tar.gz
    cd cmake-3.17.0-rc1/
    ./bootstrap
    make -j4
    sudo make install
    ```

3. Install wine from repository:
    ```
    # Add 32 bit architecture
    sudo dpkg –-add-architecture i386
    wget https://dl.winehq.org/wine-builds/Release.key
    sudo apt-key add Release.key
    sudo apt-add-repository 'https://dl.winehq.org/wine-builds/ubuntu/'
    sudo apt update
    sudo apt install wine-stable
    # Link wine binary
    sudo ln -s /opt/wine-stable/bin/wine /usr/bin/
    ```

4. Compile CMocka from sources:
- Clone cmocka repository:
    ```
    git clone https://git.cryptomilk.org/projects/cmocka.git
    ```
- Modfify `DefineOptions.cmake` file and set `BUILD_SHARED_LIBS` to `OFF` (Only needed if building for Win32)
- Build CMocka for Win32 (winagent):
  
    ```
    mkdir build
    cd build
    cmake -DCMAKE_C_COMPILER=i686-w64-mingw32-gcc -DCMAKE_C_LINK_EXECUTABLE=i686-w64-mingw32-ld -DCMAKE_INSTALL_PREFIX=/usr/i686-w64-mingw32/ -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_BUILD_TYPE=Release ..
    make
    sudo make install 
    ```
- Build CMocka for Server and Linux agent:
    ```
    cd ..
    rm -r build
    mkdir build
    cd build
    cmake -DCMAKE_BUILD_TYPE=Release ..
    make
    sudo make install 
    ```

### Compile and run tests:

1. Compile target for unit_testing:
    ```
    make deps
    make TARGET={winagent|agent|server} DEBUG=1 TEST=1
    ```

2. Compile tests: 
   ```
    cd unit_tests
    mkdir build
    cd build
    # For winagent
    cmake ../ -DCMAKE_TOOLCHAIN_FILE=../Toolchain-win32.cmake
    # For agent or server
    cmake ../
   ```

3. Run tests:
   ```
    # Full suite
    ctest
    # Parcitular test:
    cd {folder}
    wine {test_name} # (For winagent)
    {test_name} # (For agent-server)
   ```
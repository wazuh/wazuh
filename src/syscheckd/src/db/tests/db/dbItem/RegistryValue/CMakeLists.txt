cmake_minimum_required(VERSION 3.12.4)

project(registryvalue_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB registryvalue_UNIT_TEST_SRC
    "*.cpp")

file(GLOB REGISTRYVALUE_SRC "${SRC_FOLDER}/syscheckd/src/db/src/dbRegistryValue.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    file(GLOB WINDOWS_REGISTRYVALUE_SRC "${SRC_FOLDER}/syscheckd/src/db/src/fimDBSpecializationWindows.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(registryvalue_unit_test
    ${registryvalue_UNIT_TEST_SRC}
    ${REGISTRYVALUE_SRC}
    ${WINDOWS_REGISTRYVALUE_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(registryvalue_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        cjson
        crypto
        ws2_32
        crypt32
        -static-libgcc -static-libstdc++
        rsync
        dbsync
    )
else()
    target_link_libraries(registryvalue_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        sqlite3
        cjson
        crypto
        ssl
        dl
        rsync
        dbsync
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME registryvalue_unit_test
         COMMAND registryvalue_unit_test)

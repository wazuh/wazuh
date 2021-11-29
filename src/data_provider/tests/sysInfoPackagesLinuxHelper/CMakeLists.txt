cmake_minimum_required(VERSION 3.12.4)

project(sysInfoPackagesLinuxHelper_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoPackagesLinuxHelper_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoPackagesLinuxHelper_unit_test
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
    alpm
    archive
    ssl
    crypto
    cjson
    proc
    dl
)

add_test(NAME sysInfoPackagesLinuxHelper_unit_test
         COMMAND sysInfoPackagesLinuxHelper_unit_test)
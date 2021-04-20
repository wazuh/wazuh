cmake_minimum_required(VERSION 3.12.4)

project(sysInfoPackagesBerkeleyDB_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoPackagesBerkeleyDB_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoPackagesBerkeleyDB_unit_test
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
    proc
    dl
)

add_test(NAME sysInfoPackagesBerkeleyDB_unit_test
         COMMAND sysInfoPackagesBerkeleyDB_unit_test)
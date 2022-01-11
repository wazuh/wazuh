cmake_minimum_required(VERSION 3.12.4)

project(sysInfoNetworkSolaris_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/src/network/networkInterfaceSolaris.cpp")

add_executable(sysInfoNetworkSolaris_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoNetworkSolaris_unit_test
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
    dl
)

add_test(NAME sysInfoNetworkSolaris_unit_test
         COMMAND sysInfoNetworkSolaris_unit_test)

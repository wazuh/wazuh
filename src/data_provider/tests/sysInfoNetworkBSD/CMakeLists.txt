cmake_minimum_required(VERSION 3.12.4)

project(sysInfoNetworkBSD_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/src/network/networkInterfaceBSD.cpp")

add_executable(sysInfoNetworkBSD_unit_test 
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoNetworkBSD_unit_test
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
add_test(NAME sysInfoNetworkBSD_unit_test
         COMMAND sysInfoNetworkBSD_unit_test)
cmake_minimum_required(VERSION 3.12.4)

project(sysInfoProcessesMac_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "sysInfoProcessesMac_test.cpp"
    "main.cpp")

add_executable(sysInfoProcessesMac_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoProcessesMac_unit_test
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
    cjson
)

add_test(NAME sysInfoProcessesMac_unit_test
         COMMAND sysInfoProcessesMac_unit_test)

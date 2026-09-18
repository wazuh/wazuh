cmake_minimum_required(VERSION 3.12.4)

project(sysInfoProcessMac_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "sysInfoProcessMac_test.cpp"
    "main.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/src/processInfoMac.cpp")

add_executable(sysInfoProcessMac_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoProcessMac_unit_test
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
)

add_test(NAME sysInfoProcessMac_unit_test
         COMMAND sysInfoProcessMac_unit_test)

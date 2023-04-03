cmake_minimum_required(VERSION 3.12.4)

project(sysInfoSolarisPorts_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoSolarisPorts_unit_test 
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoSolarisPorts_unit_test
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

add_test(NAME sysInfoSolarisPorts_unit_test
	COMMAND sysInfoSolarisPorts_unit_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

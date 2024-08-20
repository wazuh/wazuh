cmake_minimum_required(VERSION 3.12.4)

project(sysInfoSolarisProcess_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
	"${CMAKE_SOURCE_DIR}/src/processes/processInterfaceSolaris.cpp")

add_executable(sysInfoSolarisProcess_unit_test 
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoSolarisProcess_unit_test
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

add_test(NAME sysInfoSolarisProcess_unit_test
	COMMAND sysInfoSolarisProcess_unit_test
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

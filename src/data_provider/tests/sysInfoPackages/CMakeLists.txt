cmake_minimum_required(VERSION 3.12.4)

project(sysInfoPackages_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/src/packages)
include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils/tests/mocks)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoPackages_unit_test
    ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(sysInfoPackages_unit_test
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

add_test(NAME sysInfoPackages_unit_test COMMAND sysInfoPackages_unit_test)

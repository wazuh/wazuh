cmake_minimum_required(VERSION 3.12.4)

project(sysInfoHardwareMac_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

add_executable(sysInfoHardwareMac_unit_test
    ${sysinfo_UNIT_TEST_SRC})

find_library(iokit_lib IOKit)
find_library(corefoundation_lib CoreFoundation)
  
target_link_libraries(sysInfoHardwareMac_unit_test
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
    ${iokit_lib}
    ${corefoundation_lib}
)

add_test(NAME sysInfoHardwareMac_unit_test
         COMMAND sysInfoHardwareMac_unit_test)
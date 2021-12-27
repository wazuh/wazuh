cmake_minimum_required(VERSION 3.12.4)

project(sysInfoPackageLinuxParserRPM_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB PARSER_SRC "${CMAKE_SOURCE_DIR}/src/packages/packageLinuxParserRpm.cpp")
file(GLOB RPM_SRC "${CMAKE_SOURCE_DIR}/src/packages/rpm*.cpp")

add_executable(sysInfoPackageLinuxParserRPM_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${RPM_SRC}
    ${PARSER_SRC})
set_property(TARGET sysInfoPackageLinuxParserRPM_unit_test PROPERTY COMPILE_FLAGS "-Wno-unused-parameter")
target_link_libraries(sysInfoPackageLinuxParserRPM_unit_test
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
    dl
)

add_test(NAME sysInfoPackageLinuxParserRPM_unit_test
         COMMAND sysInfoPackageLinuxParserRPM_unit_test)

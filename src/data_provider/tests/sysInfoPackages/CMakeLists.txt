cmake_minimum_required(VERSION 3.12.4)

project(sysInfoPackages_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/src/packages)
include_directories(${CMAKE_SOURCE_DIR}/../shared_modules/utils/tests/mocks)

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    file(GLOB LINUX_SRC
        "${CMAKE_SOURCE_DIR}/src/utilsWrapperLinux.cpp"
        "${CMAKE_SOURCE_DIR}/src/packages/packageLinuxParserRpm.cpp"
        "${CMAKE_SOURCE_DIR}/src/packages/packageLinuxParserDeb.cpp"
        "${CMAKE_SOURCE_DIR}/src/packages/rpm*.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

add_executable(sysInfoPackages_unit_test
    ${sysinfo_UNIT_TEST_SRC}
    ${LINUX_SRC})

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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(sysInfoPackages_unit_test
        db
        wazuhext)
endif(CMAKE_SYSTEM_NAME STREQUAL "Linux")

add_test(NAME sysInfoPackages_unit_test COMMAND sysInfoPackages_unit_test)

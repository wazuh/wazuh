cmake_minimum_required(VERSION 3.12.4)

project(sysInfoMacPackage_unit_test)

# Copy input files to the build directory
file(COPY input_files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/src/packages/packageMac.cpp")

add_executable(sysInfoMacPackage_unit_test 
    ${sysinfo_UNIT_TEST_SRC}
    ${SYSINFO_SRC})

target_link_libraries(sysInfoMacPackage_unit_test
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

if(APPLE)
  target_link_libraries(sysInfoMacPackage_unit_test ${SRC_FOLDER}/external/libplist/bin/lib/libplist-2.0.a)
endif(APPLE)

add_test(NAME sysInfoMacPackage_unit_test
         COMMAND sysInfoMacPackage_unit_test)
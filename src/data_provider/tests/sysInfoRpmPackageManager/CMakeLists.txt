cmake_minimum_required(VERSION 3.12.4)

project(RpmPackageManager_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB RPM_UNIT_TEST_SRC "*.cpp")
file(GLOB RPM_SRC "${CMAKE_SOURCE_DIR}/src/packages/rpm*.cpp")

add_executable(Rpm_unit_test ${RPM_UNIT_TEST_SRC} ${RPM_SRC})

target_link_libraries(Rpm_unit_test
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
    proc
    dl
)

add_test(NAME Rpm_unit_test
         COMMAND Rpm_unit_test)

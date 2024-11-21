cmake_minimum_required(VERSION 3.12.4)

project(sysInfoWindows_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

file(GLOB sysinfo_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYSINFO_SRC
    "${CMAKE_SOURCE_DIR}/src/utilsWrapperWin.cpp")

add_executable(sysInfoWindows_unit_test
  ${sysinfo_UNIT_TEST_SRC}
  ${SYSINFO_SRC})

link_directories("${CMAKE_SOURCE_DIR}/lib/")

target_link_libraries(sysInfoWindows_unit_test
    wbemuuid
    wuguid
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
    -static-libgcc -static-libstdc++
)

add_test(NAME sysInfoWindows_unit_test
    COMMAND sysInfoWindows_unit_test)

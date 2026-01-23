cmake_minimum_required(VERSION 3.12.4)

project(dbsync_unit_test)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)

file(GLOB INTERFACE_UNITTEST_SRC "*.cpp"
     "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
     "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(dbsync_unit_test ${INTERFACE_UNITTEST_SRC})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    dbsync_unit_test
    debug
    gtestd
    debug
    gmockd
    debug
    gtest_maind
    debug
    gmock_maind
    optimized
    gtest
    optimized
    gmock
    optimized
    gtest_main
    optimized
    gmock_main
    sqlite3
    cjson
    crypto
    ssl
    pthread
    -static-libgcc
    -static-libstdc++
    ws2_32
    crypt32)
else()
  target_link_libraries(
    dbsync_unit_test
    debug
    gtestd
    debug
    gmockd
    debug
    gtest_maind
    debug
    gmock_maind
    optimized
    gtest
    optimized
    gmock
    optimized
    gtest_main
    optimized
    gmock_main
    sqlite3
    crypto
    cjson
    pthread
    dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME dbsync_unit_test COMMAND dbsync_unit_test)

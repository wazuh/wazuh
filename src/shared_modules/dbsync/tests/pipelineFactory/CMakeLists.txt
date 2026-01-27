cmake_minimum_required(VERSION 3.12.4)

project(dbsyncPipelineFactory_unit_test)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/shared_modules/dbsync/src/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
link_directories(${CMAKE_BINARY_DIR}/lib)

file(GLOB PIPELINE_FACTORY_UNITTEST_SRC "*.cpp")

include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)

file(GLOB PIPELINE_FACTORY_SRC "${SRC_FOLDER}/shared_modules/dbsync/src/*.cpp"
     "${SRC_FOLDER}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(dbsyncPipelineFactory_unit_test ${PIPELINE_FACTORY_UNITTEST_SRC}
                                               ${PIPELINE_FACTORY_SRC})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    dbsyncPipelineFactory_unit_test
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
    pthread
    sqlite3
    cjson
    crypto
    ssl
    -static-libgcc
    -static-libstdc++
    ws2_32
    crypt32)
else()
  target_link_libraries(
    dbsyncPipelineFactory_unit_test
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
    pthread
    sqlite3
    crypto
    cjson
    dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME dbsyncPipelineFactory_unit_test
         COMMAND dbsyncPipelineFactory_unit_test)

set_tests_properties(dbsyncPipelineFactory_unit_test PROPERTIES LABELS "dbsync")

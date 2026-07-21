cmake_minimum_required(VERSION 3.12.4)

project(remoted_module_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

file(GLOB UNIT_SRC_FILES ${UNIT_SRC_DIR}/*.cpp)

add_executable(remoted_module_utest ${UNIT_SRC_FILES})

target_link_libraries(
  remoted_module_utest
  debug gtestd
  debug gmockd
  debug gtest_maind
  debug gmock_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  optimized gmock_main
  remoted_module
  pthread)

target_include_directories(
  remoted_module_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${CMAKE_CURRENT_LIST_DIR}/../interface
          ${CMAKE_CURRENT_LIST_DIR}/../src # http_server/ internal headers
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON)

add_test(NAME remoted_module_utest COMMAND remoted_module_utest)
set_tests_properties(remoted_module_utest PROPERTIES LABELS remoted_module_utest)

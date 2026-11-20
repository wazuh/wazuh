cmake_minimum_required(VERSION 3.12.4)

project(extended_sources_groups_unit_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(TEST_SRC "main.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND TEST_SRC test_groups_windows.cpp)
  list(APPEND TEST_SRC test_user_groups_windows.cpp)
else()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND TEST_SRC test_groups_linux.cpp)
    list(APPEND TEST_SRC test_user_groups_linux.cpp)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND TEST_SRC test_groups_darwin.cpp)
    list(APPEND TEST_SRC test_user_groups_darwin.cpp)
  endif()
endif()

add_executable(extended_sources_groups_unit_test ${TEST_SRC})

target_link_libraries(
  extended_sources_groups_unit_test
  groups
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
  gmock_main)

add_test(NAME GroupsTests COMMAND extended_sources_groups_unit_test)

set_tests_properties(GroupsTests PROPERTIES LABELS "data_provider")

cmake_minimum_required(VERSION 3.12.4)
project(ebpf_unit_tests)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../ ABSOLUTE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${CMAKE_CURRENT_SOURCE_DIR}/../src
  ${SRC_FOLDER}/external/googletest/googletest/include
  ${SRC_FOLDER}/external/googletest/googlemock/include
  ${SRC_FOLDER}/shared/include
)

add_executable(
  ebpf_test
  unit/ebpf_loader_test.cpp
)

target_link_libraries(
  ebpf_test
  PRIVATE
    ebpf
    gtest
    gmock
    gtest_main
    pthread
)

add_test(NAME ebpf_test COMMAND ebpf_test)

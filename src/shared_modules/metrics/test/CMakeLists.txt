cmake_minimum_required(VERSION 3.12.4)

project(wazuh_metrics_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
link_directories(${SRC_FOLDER}/external/googletest/lib)

file(GLOB UNIT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/unit/*.cpp)

add_executable(wazuh_metrics_utest ${UNIT_SRC_FILES})

target_link_libraries(
  wazuh_metrics_utest
  debug gtestd
  debug gmockd
  debug gtest_maind
  debug gmock_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  optimized gmock_main
  wazuh_metrics
  pthread)

target_include_directories(
  wazuh_metrics_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/mocks
          ${SRC_FOLDER}/external/nlohmann)

add_test(NAME wazuh_metrics_utest COMMAND wazuh_metrics_utest)
set_tests_properties(wazuh_metrics_utest PROPERTIES LABELS wazuh_metrics_utest)

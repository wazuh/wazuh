cmake_minimum_required(VERSION 3.12.4)

project(sysInfoNetworkLinux_unit_test)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

file(GLOB sysinfo_UNIT_TEST_SRC "*.cpp")

file(GLOB SYSINFO_SRC
     "${SRC_FOLDER}/data_provider/src/network/networkInterfaceLinux.cpp")

add_executable(sysInfoNetworkLinux_unit_test ${sysinfo_UNIT_TEST_SRC}
                                             ${SYSINFO_SRC})

target_link_libraries(
  sysInfoNetworkLinux_unit_test
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
  dl)

add_test(NAME sysInfoNetworkLinux_unit_test
         COMMAND sysInfoNetworkLinux_unit_test)

set_tests_properties(sysInfoNetworkLinux_unit_test PROPERTIES LABELS "data_provider")

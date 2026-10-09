cmake_minimum_required(VERSION 3.12.4)

project(sysInfoHardwareLinux_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC "*.cpp")

add_executable(sysInfoHardwareLinux_unit_test ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(
  sysInfoHardwareLinux_unit_test
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
  pthread)

add_test(NAME sysInfoHardwareLinux_unit_test
         COMMAND sysInfoHardwareLinux_unit_test)

set_tests_properties(sysInfoHardwareLinux_unit_test PROPERTIES LABELS "data_provider")

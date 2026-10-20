cmake_minimum_required(VERSION 3.12.4)

project(sysInfoRpmDbReaders_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC "*.cpp")

add_executable(sysInfoRpmDbReaders_unit_test ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(
  sysInfoRpmDbReaders_unit_test
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
  dl)

add_test(NAME sysInfoRpmDbReaders_unit_test
         COMMAND sysInfoRpmDbReaders_unit_test)

set_tests_properties(sysInfoRpmDbReaders_unit_test PROPERTIES LABELS "data_provider")

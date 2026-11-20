cmake_minimum_required(VERSION 3.12.4)

project(sysInfoPackageDbParser_unit_test)

file(GLOB sysinfo_UNIT_TEST_SRC "*.cpp")

add_executable(sysInfoPackageDbParser_unit_test ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(
  sysInfoPackageDbParser_unit_test
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
  db
  dl)

# Databases for the Berkeley DB read: a valid one, and two damaged ones that hang and crash libdb.
target_compile_definitions(
  sysInfoPackageDbParser_unit_test
  PRIVATE PACKAGE_DB_FIXTURES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

add_test(NAME sysInfoPackageDbParser_unit_test
         COMMAND sysInfoPackageDbParser_unit_test)

set_tests_properties(sysInfoPackageDbParser_unit_test PROPERTIES LABELS "data_provider")

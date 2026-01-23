cmake_minimum_required(VERSION 3.12.4)

project(sysInfoWindows_unit_test)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

file(GLOB sysinfo_UNIT_TEST_SRC "*.cpp")

file(GLOB SYSINFO_SRC "${SRC_FOLDER}/data_provider/src/utilsWrapperWin.cpp")

add_executable(sysInfoWindows_unit_test ${sysinfo_UNIT_TEST_SRC} ${SYSINFO_SRC})

link_directories("${SRC_FOLDER}/data_provider/lib/")

target_link_libraries(
  sysInfoWindows_unit_test
  wbemuuid
  wuguid
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
  -static-libgcc
  -static-libstdc++)

add_test(NAME sysInfoWindows_unit_test COMMAND sysInfoWindows_unit_test)

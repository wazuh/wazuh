cmake_minimum_required(VERSION 3.12.4)

project(sysInfoHardwareMac_unit_test)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

file(
  GLOB sysinfo_UNIT_TEST_SRC
  "${SRC_FOLDER}/data_provider/src/hardware/*X86_64Mac.cpp"
  "sysInfoHardwareMac_test.cpp" "sysInfoHardwareWrapperMac_test.cpp" "main.cpp")

add_executable(sysInfoHardwareMac_unit_test ${sysinfo_UNIT_TEST_SRC})

target_link_libraries(
  sysInfoHardwareMac_unit_test
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
  cjson)

add_test(NAME sysInfoHardwareMac_unit_test COMMAND sysInfoHardwareMac_unit_test)

set_tests_properties(sysInfoHardwareMac_unit_test PROPERTIES LABELS "data_provider")

if(${CMAKE_HOST_SYSTEM_PROCESSOR} MATCHES "arm64.*|ARM64.*")
  file(GLOB sysinfo_ARM_UNIT_TEST_SRC
       "${SRC_FOLDER}/data_provider/src/hardware/*ARMMac.cpp"
       "sysInfoHardwareWrapperARMMac_test.cpp" "main.cpp")

  add_executable(sysInfoHardwareARMMac_unit_test ${sysinfo_ARM_UNIT_TEST_SRC})

  find_library(iokit_lib IOKit)
  if(NOT iokit_lib)
    message(FATAL_ERROR "IOKit library not found! Aborting...")
  endif()
  find_library(corefoundation_lib CoreFoundation)
  if(NOT corefoundation_lib)
    message(FATAL_ERROR "CoreFoundation library not found! Aborting...")
  endif()

  target_link_libraries(
    sysInfoHardwareARMMac_unit_test
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
    cjson
    ${iokit_lib}
    ${corefoundation_lib})

  add_test(NAME sysInfoHardwareARMMac_unit_test
           COMMAND sysInfoHardwareARMMac_unit_test)

  set_tests_properties(sysInfoHardwareARMMac_unit_test PROPERTIES LABELS "data_provider")
endif()

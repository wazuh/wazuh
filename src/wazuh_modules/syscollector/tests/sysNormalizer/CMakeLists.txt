cmake_minimum_required(VERSION 3.12.4)

project(sys_normalizer_unit_test)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

file(GLOB SYS_NORMALIZER_UNIT_TEST_SRC "*.cpp")

file(GLOB SYS_NORMALIZER_SRC
     "${SRC_FOLDER}/wazuh_modules/syscollector/src/syscollectorNormalizer.cpp")

add_executable(sys_normalizer_unit_test ${SYS_NORMALIZER_UNIT_TEST_SRC}
                                        ${SYS_NORMALIZER_SRC})
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    sys_normalizer_unit_test
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
    -static-libgcc
    -static-libstdc++)
else()
  target_link_libraries(
    sys_normalizer_unit_test
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
    dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME sys_normalizer_unit_test COMMAND sys_normalizer_unit_test)

set_tests_properties(sys_normalizer_unit_test PROPERTIES LABELS "syscollector")

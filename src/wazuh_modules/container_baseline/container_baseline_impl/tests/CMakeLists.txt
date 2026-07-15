cmake_minimum_required(VERSION 3.12.4)

project(container_baseline_unit_test)

file(GLOB CONTAINER_BASELINE_UNIT_TEST_SRC "*.cpp")

add_executable(container_baseline_unit_test ${CONTAINER_BASELINE_UNIT_TEST_SRC})

target_include_directories(container_baseline_unit_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    container_baseline_unit_test
    CONTAINER_BASELINE_IMPL
    debug gtestd debug gtest_maind
    optimized gtest optimized gtest_main
    pthread
    -static-libgcc
    -static-libstdc++)
else()
  target_link_libraries(
    container_baseline_unit_test
    CONTAINER_BASELINE_IMPL
    debug gtestd debug gtest_maind
    optimized gtest optimized gtest_main
    pthread
    dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME container_baseline_unit_test COMMAND container_baseline_unit_test)

set_tests_properties(container_baseline_unit_test PROPERTIES LABELS "container_baseline")

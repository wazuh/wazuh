cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(BUILDER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/builder)
set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

# Builder test
add_executable(builder_test ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp)
target_include_directories(builder_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(builder_test gtest_main)
gtest_discover_tests(builder_test)

# Configuration test
add_executable(configuration_test ${BUILDER_TEST_SOURCE_DIR}/configuration_test.cpp)
target_include_directories(configuration_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(configuration_test gtest_main)
gtest_discover_tests(configuration_test)

# Processor test
add_executable(processor_test ${BUILDER_TEST_SOURCE_DIR}/processor_test.cpp)
target_include_directories(processor_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(processor_test gtest_main)
gtest_discover_tests(processor_test)

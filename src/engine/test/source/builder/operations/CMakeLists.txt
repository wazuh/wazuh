cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(OPERATIONS_TEST_SOURCE_DIR ${BUILDER_TEST_SOURCE_DIR}/operations)
set(OPERATIONS_ENGINE_SOURCE_DIR ${BUILDER_ENGINE_SOURCE_DIR}/operations)

# condition_builder test
add_executable(condition_builder_test ${OPERATIONS_TEST_SOURCE_DIR}/condition_builder_test.cpp ${OPERATIONS_ENGINE_SOURCE_DIR}/condition_builder.cpp ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp)
target_include_directories(condition_builder_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(condition_builder_test gtest_main rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(condition_builder_test)

# condition_value test
add_executable(condition_value_test ${OPERATIONS_TEST_SOURCE_DIR}/condition_value_test.cpp ${OPERATIONS_ENGINE_SOURCE_DIR}/condition_value.cpp ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp)
target_include_directories(condition_value_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(condition_value_test gtest_main rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(condition_value_test)

# helper_exists test
add_executable(helper_exists_test ${OPERATIONS_TEST_SOURCE_DIR}/helper_exists_test.cpp ${OPERATIONS_ENGINE_SOURCE_DIR}/helper_exists.cpp ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp)
target_include_directories(helper_exists_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(helper_exists_test gtest_main rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(helper_exists_test)

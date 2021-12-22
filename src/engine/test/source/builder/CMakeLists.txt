cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(BUILDER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/builder)
set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

# Builder test
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)

add_executable(builder_test ${BUILDER_TEST_SOURCE_DIR}/builder_test.cpp ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp)
target_include_directories(builder_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(builder_test gtest_main rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(builder_test)

# Registry test
add_executable(registry_test ${BUILDER_TEST_SOURCE_DIR}/registry_test.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp)
target_include_directories(registry_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(registry_test gtest_main)
gtest_discover_tests(registry_test)

# Utils test
add_executable(utils_test ${BUILDER_TEST_SOURCE_DIR}/utils_test.cpp ${BUILDER_ENGINE_SOURCE_DIR}/utils.cpp ${BUILDER_ENGINE_SOURCE_DIR}/builder.cpp ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp)
target_include_directories(utils_test PUBLIC ${BUILDER_ENGINE_SOURCE_DIR})
target_link_libraries(utils_test gtest_main rxcpp nlohmann_json::nlohmann_json)
gtest_discover_tests(utils_test)

# Operations tests
add_subdirectory(operations)

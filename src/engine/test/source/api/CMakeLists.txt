add_executable(api_test_deprecated
    registry_test.cpp
    adapter_test.cpp
    api_test.cpp
)
target_include_directories(api_test_deprecated
PRIVATE
${TEST_SOURCE_DIR}/common
)
target_link_libraries(api_test_deprecated gtest_main base api)
gtest_discover_tests(api_test_deprecated)

add_subdirectory(catalog)
add_subdirectory(kvdb)
add_subdirectory(integration)

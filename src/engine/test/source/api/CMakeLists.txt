add_executable(api_test
    registry_test.cpp
    adapter_test.cpp
    api_test.cpp
)
target_include_directories(api_test
PRIVATE
${TEST_SOURCE_DIR}/common
)
target_link_libraries(api_test gtest_main base api)
gtest_discover_tests(api_test)

add_subdirectory(catalog)
add_subdirectory(kvdb)
add_subdirectory(integration)
add_subdirectory(graph)

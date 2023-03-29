add_executable(json_test
    json_test.cpp
)

target_include_directories(json_test
    PUBLIC
    ${ENGINE_SOURCE_DIR}/json
    ${TEST_SOURCE_DIR}/base/utils/tests
)

# TODO check if it's ok to add base for the json dep
target_link_libraries(json_test gtest_main base)
gtest_discover_tests(json_test)

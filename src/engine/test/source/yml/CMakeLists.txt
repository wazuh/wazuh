add_executable(yml_test
    yml_test.cpp
)

target_include_directories(yml_test
    PUBLIC
    ${ENGINE_SOURCE_DIR}/yml
    ${TEST_SOURCE_DIR}/common
)

# TODO check if it's ok to add base for the json dep
target_link_libraries(yml_test test_mocks gtest_main base yml)
gtest_discover_tests(yml_test)

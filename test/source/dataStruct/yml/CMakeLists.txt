add_executable(utilsYml_test
    utilsYml_test.cpp
)

target_include_directories(utilsYml_test
    PUBLIC
    ${ENGINE_SOURCE_DIR}/dataStruct/yml
    ${TEST_SOURCE_DIR}/common
)

# TODO check if it's ok to add base for the json dep
target_link_libraries(utilsYml_test test_mocks gtest_main base yml)
gtest_discover_tests(utilsYml_test)

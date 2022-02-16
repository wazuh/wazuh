CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG master
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
)

# Configuration Catalog tests
add_executable(hlp_test
  ${TEST_SOURCE_DIR}/hlp/hlp_test.cpp
)

target_link_libraries(hlp_test hlp gtest_main)

gtest_discover_tests(hlp_test)

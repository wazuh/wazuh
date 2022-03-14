
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

add_executable(kvdb_test
  ${TEST_SOURCE_DIR}/kvdb/kvdb_test.cpp
)

target_include_directories(kvdb_test PUBLIC "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/")

target_link_libraries(kvdb_test kvdb gtest_main)

gtest_discover_tests(kvdb_test)

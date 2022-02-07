# dependencies
# Processor test
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  OPTIONS
    "MAKE_BUILD_TYPE RelWithDebInfo"
)

CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG master
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
        # "RAPIDJSON_BUILD_CXX17 ON"
)

# Configuration rxcpp test
add_executable(rxcpp_test 
  ${TEST_SOURCE_DIR}/rxcpp/rxcpp_test.cpp
  ${TEST_SOURCE_DIR}/rxcpp/rxcpp_test.hpp
)

target_include_directories(rxcpp_test PRIVATE "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/" )
target_link_libraries(rxcpp_test gtest_main benchmark::benchmark_main rxcpp)
gtest_discover_tests(rxcpp_test)

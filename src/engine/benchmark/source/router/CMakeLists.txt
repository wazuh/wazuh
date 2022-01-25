
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
    GIT_TAG v1.1.0
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
        # "RAPIDJSON_BUILD_CXX17 ON"
)

# Add unit benchmarks here

# Configuration router test
add_executable(router_benchmarks
  ${BENCHMARK_SOURCE_DIR}/router/router_bench.cpp
  ${ENGINE_SOURCE_DIR}/router/router.hpp
)

# Build benchmarks
target_include_directories(router_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/" )
target_link_libraries(router_benchmarks benchmark::benchmark_main rxcpp "nlohmann_json::nlohmann_json")

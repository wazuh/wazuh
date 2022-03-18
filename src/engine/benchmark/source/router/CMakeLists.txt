# Add unit benchmarks here

# Configuration router test
add_executable(router_benchmarks
  ${BENCHMARK_SOURCE_DIR}/router/router_bench.cpp
  ${ENGINE_SOURCE_DIR}/router/router.hpp
)

# Build benchmarks
target_include_directories(router_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/" )
target_link_libraries(router_benchmarks benchmark::benchmark_main rxcpp "nlohmann_json::nlohmann_json")

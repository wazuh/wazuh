add_executable(router_benchmarks
  router_bench.cpp
)

# target_include_directories(router_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/router")
target_link_libraries(router_benchmarks benchmark::benchmark_main base router builders rxbk)

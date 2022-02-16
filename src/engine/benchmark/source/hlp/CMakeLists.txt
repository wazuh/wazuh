add_executable(hlp_benchmarks
  ${BENCHMARK_SOURCE_DIR}/hlp/hlp_bench.cpp
)

target_include_directories(hlp_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/hlp")
target_link_libraries(hlp_benchmarks benchmark::benchmark_main hlp)

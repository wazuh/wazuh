add_executable(hlp2_benchmarks
  hlp2_bench.cpp
)

target_include_directories(hlp2_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/hlp2")
target_link_libraries(hlp2_benchmarks benchmark::benchmark_main hlp2)

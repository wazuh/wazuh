add_executable(hlp3_benchmarks
  hlp3_bench.cpp
)

target_include_directories(hlp3_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/hlp3")
target_link_libraries(hlp3_benchmarks benchmark::benchmark_main hlp3)

add_executable(base_benchmarks
parseEvent_bench.cpp
)

target_include_directories(base_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/base")
target_link_libraries(base_benchmarks benchmark::benchmark_main base)

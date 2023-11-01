add_executable(queue_benchmarks
  single_and_double_priority.cpp
)

target_link_libraries(queue_benchmarks benchmark::benchmark_main test_mocks queue)

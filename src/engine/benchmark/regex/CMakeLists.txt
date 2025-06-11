# Configuration regex test
add_executable(regex_bench
  regex_bench.cpp
)

# Build benchmarks
target_link_libraries(regex_bench benchmark::benchmark_main re2::re2)

# dependencies
CPMAddPackage(
  NAME RE2
  GITHUB_REPOSITORY google/re2
  GIT_TAG 2022-02-01
  VERSION release 2022-02-01
)

# Configuration regex test
add_executable(regex_bench
  regex_bench.cpp
)

# Build benchmarks
target_link_libraries(regex_bench benchmark::benchmark_main re2)

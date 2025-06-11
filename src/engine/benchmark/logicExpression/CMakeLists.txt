add_executable(logicExpression_benchmarks
  evaluator_bench.cpp
)

target_link_libraries(logicExpression_benchmarks benchmark::benchmark_main logicexpr)

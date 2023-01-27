add_executable(helpersFunctions_benchmarks
    filters_bench.cpp
)

# TODO Why is necessary add logixExpression
target_include_directories(helpersFunctions_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/builder")
target_link_libraries(helpersFunctions_benchmarks benchmark::benchmark_main logicExpression builders base)

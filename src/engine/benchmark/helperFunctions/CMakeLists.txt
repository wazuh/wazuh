add_executable(helpersFunctions_benchmarks
    filters_bench.cpp
)

# TODO: Because is necessary to add logicExpressions (This shoulb be changed public in builder)
target_include_directories(helpersFunctions_benchmarks PRIVATE "${ENGINE_SOURCE_DIR}/builder")
target_link_libraries(helpersFunctions_benchmarks benchmark::benchmark_main logicexpr builders base defs::mocks)

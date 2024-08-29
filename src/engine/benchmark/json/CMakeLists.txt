add_executable(jsonSearch_benchmark
    ${CMAKE_CURRENT_LIST_DIR}/jsonSearch_benchmark.cpp
)
target_link_libraries(jsonSearch_benchmark base benchmark::benchmark_main)

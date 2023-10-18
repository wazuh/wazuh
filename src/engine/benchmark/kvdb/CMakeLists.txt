add_executable(kvdb_bench kvdb_bench.cpp)

target_link_libraries(kvdb_bench
    engine_bench_main
    kvdb::ikvdb
    )

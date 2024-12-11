if(NOT CMAKE_BUILD_TYPE STREQUAL "Release"
        AND NOT CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    message(WARNING
        "Building and running benchmarks with a non release build will give bogus data"
        )
endif()

add_library(engine_bench_main
    OBJECT
    wazuhBenchMain.cpp
    )

target_link_libraries(engine_bench_main
    PUBLIC
    benchmark::benchmark
    base
    metrics
    )

add_subdirectory(regex)
add_subdirectory(hlp)
add_subdirectory(logicExpression)
add_subdirectory(base)
# add_subdirectory(helperFunctions) TODO Implment after refactoring
add_subdirectory(json)

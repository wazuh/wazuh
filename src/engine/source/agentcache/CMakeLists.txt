####################################################################################################
# AGENT CACHE
####################################################################################################
# Header-only cache of parsed agent metadata (header JSON) for the enriched-events path.
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(agentcache_agentcache INTERFACE)
target_include_directories(agentcache_agentcache INTERFACE ${INC_DIR})
target_link_libraries(agentcache_agentcache
    INTERFACE
    base
    fastmetrics::fastmetrics
)
add_library(agentcache::agentcache ALIAS agentcache_agentcache)

# Tests

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(agentcache_utest
    ${UNIT_SRC_DIR}/agentMetadataCache_test.cpp
)
target_link_libraries(agentcache_utest
    PRIVATE
    agentcache::agentcache
    GTest::gtest_main
)
gtest_discover_tests(agentcache_utest)

endif(ENGINE_BUILD_TEST)

if(ENGINE_BUILD_BENCHMARK)

set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_executable(agentcache_benchmark
    ${BENCH_SRC_DIR}/agentMetadataCache_bench.cpp
)
target_link_libraries(agentcache_benchmark
    PRIVATE
    agentcache::agentcache
    benchmark::benchmark
    benchmark::benchmark_main
)

endif(ENGINE_BUILD_BENCHMARK)

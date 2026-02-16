# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/test)

# Interface
add_library(fastqueue_ifastqueue INTERFACE)
target_include_directories(fastqueue_ifastqueue INTERFACE ${IFACE_DIR})
target_link_libraries(fastqueue_ifastqueue INTERFACE base)
add_library(fastqueue::ifastqueue ALIAS fastqueue_ifastqueue)

# fastqueue
add_library(fastqueue_fasqueue STATIC
  ${SRC_DIR}/cqueue.cpp)

# target_link_libraries(fastqueue
target_include_directories(fastqueue_fasqueue
  PUBLIC
  ${INC_DIR}
)

target_link_libraries(fastqueue_fasqueue
  PUBLIC
  fastqueue::ifastqueue
  unofficial-concurrentqueue::concurrentqueue
)

add_library(fastqueue::fastqueue ALIAS fastqueue_fasqueue)

# Tests
if(ENGINE_BUILD_TEST)
  set(TEST_SRC_DIR ${TEST_DIR}/src)
  set(TEST_SRC_COMPONENT_DIR ${TEST_SRC_DIR}/component)
  set(TEST_SRC_UNIT_DIR ${TEST_SRC_DIR}/unit)
  set(TEST_MOCK_DIR ${TEST_DIR}/mocks)

  # Mocks
  add_library(fastqueue_mocks INTERFACE)
  target_include_directories(fastqueue_mocks INTERFACE ${TEST_MOCK_DIR})
  target_link_libraries(fastqueue_mocks INTERFACE GTest::gmock fastqueue)
  add_library(fastqueue::mocks ALIAS fastqueue_mocks)

  # Component test
  add_executable(fastqueue_ctest
    ${TEST_SRC_COMPONENT_DIR}/cqueue_test.cpp
    ${TEST_SRC_COMPONENT_DIR}/stdqueue_test.cpp
  )

  target_link_libraries(fastqueue_ctest
    GTest::gtest_main
    base
    fastqueue::fastqueue
    # TODO: Until the indexer connector is unified with the rest of wazuh-manager
    # metrics::mocks
    base::test
  )
  gtest_discover_tests(fastqueue_ctest)

endif(ENGINE_BUILD_TEST)

# Benchmarks
if(ENGINE_BUILD_BENCHMARK)

set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)

add_library(fastqueue_bench INTERFACE)

target_include_directories(fastqueue_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(fastqueue_bench INTERFACE fastqueue::fastqueue benchmark::benchmark)
add_library(fastqueue::bench ALIAS fastqueue_bench)

add_executable(fastqueue_benchmark
    ${BENCH_SRC_DIR}/cqueue_bench.cpp
    ${BENCH_SRC_DIR}/stdqueue_bench.cpp
    ${BENCH_SRC_DIR}/comparison_bench.cpp
)

target_include_directories(fastqueue_benchmark
    PRIVATE
    ${BENCH_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}
)

target_link_libraries(fastqueue_benchmark
    PUBLIC
    fastqueue::bench
    benchmark::benchmark_main
)

endif(ENGINE_BUILD_BENCHMARK)

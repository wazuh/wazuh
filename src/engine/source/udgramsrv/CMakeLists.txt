# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

set(SRCS
    ${SRC_DIR}/udsrv.cpp
)
set(PRIVATE_LINKS
    base
)

add_library(udgramsrv
    ${SRCS}
)
target_include_directories(udgramsrv
    PUBLIC
    ${INC_DIR}
    PRIVATE
    ${SRC_DIR}
)

target_link_libraries(udgramsrv
    PRIVATE
    ${PRIVATE_LINKS}
)

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(udgramsrv_ctest
    ${COMPONENT_SRC_DIR}/udgramsrv_test.cpp
)
target_include_directories(udgramsrv_ctest
    PRIVATE
    ${COMPONENT_SRC_DIR}
)
target_link_libraries(udgramsrv_ctest
    udgramsrv
    base
    GTest::gtest_main
)
gtest_discover_tests(udgramsrv_ctest)

endif(ENGINE_BUILD_TEST)

if(ENGINE_BUILD_BENCHMARK)
set(BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark)
set(BENCH_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/benchmark/src)
add_library(udgramsrv_bench INTERFACE)
target_include_directories(udgramsrv_bench INTERFACE ${BENCH_DIR}/include)
target_link_libraries(udgramsrv_bench INTERFACE udgramsrv benchmark::benchmark)
add_library(udgramsrv::bench ALIAS udgramsrv_bench)
add_executable(udgramsrv_benchmark
    ${BENCH_SRC_DIR}/udgramsrv_bench.cpp
)
target_include_directories(udgramsrv_benchmark
    PRIVATE
    ${BENCH_SRC_DIR}
    ${SRC_DIR}
    ${INC_DIR}
)
target_link_libraries(udgramsrv_benchmark
    PUBLIC
    udgramsrv::bench
    benchmark::benchmark_main
)

endif(ENGINE_BUILD_BENCHMARK)

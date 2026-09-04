cmake_minimum_required(VERSION 3.10)
project(fim_ebpf_unit_tests)

set(CMAKE_CXX_STANDARD 14)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(bounded_queue_test bounded_queue_test.cpp)

target_link_libraries(bounded_queue_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
)

add_test(NAME bounded_queue_test
         COMMAND bounded_queue_test)

# Staging buffer between the eBPF drain and the container reconcile consumer
# (#37532 / #37396). Header-only and I/O-free, so all of it is reachable from a
# unit test — which is why it is a separate component from the drain and the
# consumer in the first place.
add_executable(container_event_staging_test container_event_staging_test.cpp)

target_link_libraries(container_event_staging_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME container_event_staging_test
         COMMAND container_event_staging_test)

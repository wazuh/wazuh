cmake_minimum_required(VERSION 3.10)
project(container_attribution_unit_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

# The map is header-only and I/O-free: resolution is fed in by the owner rather
# than queried here, which is what makes the inode-reuse cases testable at all.
add_executable(cgroup_container_map_test cgroup_container_map_test.cpp)

target_link_libraries(cgroup_container_map_test
    container_attribution
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME cgroup_container_map_test
         COMMAND cgroup_container_map_test)

add_executable(container_list_refresh_test container_list_refresh_test.cpp)

target_link_libraries(container_list_refresh_test
    container_attribution
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME container_list_refresh_test
         COMMAND container_list_refresh_test)

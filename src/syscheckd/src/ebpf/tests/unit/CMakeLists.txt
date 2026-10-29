cmake_minimum_required(VERSION 3.10)
project(fim_ebpf_unit_tests)

set(CMAKE_CXX_STANDARD 17)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(bounded_queue_test bounded_queue_test.cpp)

target_link_libraries(bounded_queue_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

if(FSANITIZE)
    target_link_libraries(bounded_queue_test
        -fsanitize=address
        -fsanitize=undefined
    )
endif(FSANITIZE)

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

# cgroup_id -> container_id attribution for the drain (#37532 / #37396). Also
# header-only and I/O-free: resolution is fed in by the owner rather than
# queried here, which is what makes the inode-reuse cases testable at all.
add_executable(cgroup_container_map_test cgroup_container_map_test.cpp)

target_link_libraries(cgroup_container_map_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME cgroup_container_map_test
         COMMAND cgroup_container_map_test)

# The policy joining the two above (#37532 / #37396): what the drain does with
# an event, and what it does with reported loss. Kept out of the drain itself so
# it is reachable without a kernel, a BPF object or root.
add_executable(container_event_router_test container_event_router_test.cpp)

target_link_libraries(container_event_router_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME container_event_router_test
         COMMAND container_event_router_test)

# D15 (12-blocking-decisions.md): a path reconcile may never authorise delete
# detection. Enforced by the type the consumer acts on rather than by a comment
# asking it to behave.
add_executable(container_reconcile_plan_test container_reconcile_plan_test.cpp)

target_link_libraries(container_reconcile_plan_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME container_reconcile_plan_test
         COMMAND container_reconcile_plan_test)

# How long the container resolver blocks between passes (#37532 / #37396). Split
# out of the drain so it is reachable without a thread, a socket or a kernel —
# the same reason every other component above lives in its own header.
add_executable(resolver_wait_test resolver_wait_test.cpp)

target_link_libraries(resolver_wait_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME resolver_wait_test
         COMMAND resolver_wait_test)

# The container FIM document budget's decision rule (#37532 / O10). Split out of
# the bridge for the same reason as everything above it: the rule otherwise sits
# beside a process-global counter and a pthread mutex inside a .c, reachable only
# by running the daemon — and a budget nobody can test is how the host path's own
# accounting drifted.
add_executable(container_doc_budget_test container_doc_budget_test.cpp)

target_link_libraries(container_doc_budget_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME container_doc_budget_test
         COMMAND container_doc_budget_test)

# The per-container row ceiling and the delete-safety rule it enables
# (#37532 / O10). Split out of the baseline transaction for the same reason as
# everything above: the rules otherwise run only against a real database, and
# the one that decides whether deletions are suppressed is the one that must
# never silently change.
add_executable(container_row_budget_test container_row_budget_test.cpp)

target_link_libraries(container_row_budget_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_test(NAME container_row_budget_test
         COMMAND container_row_budget_test)

add_executable(container_reporting_test
    container_reporting_test.cpp
    container_reporting_test_host.c
    ../../src/container_baseline_fim.cpp
    ../../src/container_baseline_fim_bridge.c
    ../../src/container_event_drain.cpp)
target_link_libraries(container_reporting_test
    debug gtestd debug gtest_maind
    optimized gtest optimized gtest_main
    wazuh container_baseline rt_engine fimdb pthread)
target_link_options(container_reporting_test PRIVATE
    -Wl,--wrap=fim_collect_container_monitored_paths
    -Wl,--wrap=fim_free_container_monitored_paths
    -Wl,--wrap=fim_container_baseline_available
    -Wl,--wrap=cbaseline_list_containers_ex
    -Wl,--wrap=cbaseline_run_fim_dbsync
    -Wl,--wrap=_mdebug1
    -Wl,--wrap=_minfo
    -Wl,--wrap=_mwarn
    -Wl,--wrap=_merror)
add_test(NAME container_reporting_test COMMAND container_reporting_test)

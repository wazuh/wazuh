cmake_minimum_required(VERSION 3.10)
project(fim_ebpf_whodata_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/shared/include/)
include_directories(${SRC_FOLDER}/syscheckd/include/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

# init_libbpf_test.cpp / init_bpf_obj_test.cpp / init_ring_buffer_test.cpp /
# close_libbpf_test.cpp were removed in the #37396/#37533 cutover: they
# tested libbpf load/attach/ring-buffer internals that moved to
# src/shared_modules/ebpf_provider/ (rt_engine), which has no unit tests of
# its own yet (see that directory's CMakeLists.txt comment) — a real gap
# flagged, not silently dropped.
set(TEST_FILES
    ebpf_whodata_test.cpp
    healthcheck_event_test.cpp
    pop_event_test.cpp)

# Create an executable for each test file
foreach(TEST_FILE ${TEST_FILES})
  get_filename_component(TEST_NAME "${TEST_FILE}" NAME_WE)
  # link_stubs.cpp: fimebpf.so also contains container_baseline_fim.cpp/
  # container_baseline_fim_bridge.c/container_live_fim.cpp, which call into
  # syscheckd_lib/fimdb/agent_sync_protocol (validate_and_persist_fim_event,
  # the `syscheck` global, fim_db_*). None of THESE tests exercise that code
  # path, but the linker still needs those symbols resolved because they're
  # in the same .so. Linking the real syscheckd_lib/fimdb/agent_sync_protocol
  # turned out to be a genuine circular CMake target dependency (syscheckd_
  # lib -> fimebpf -> ... -> wazuh_modulesd_lib/syscollector -> back to
  # fimebpf) that CMake's own LINK_GROUP cycle validation refuses to build —
  # narrow stubs sidestep that fight entirely.
  add_executable("${TEST_NAME}" "${TEST_FILE}" link_stubs.cpp)
  target_link_libraries(
    ${TEST_NAME}
    PRIVATE debug
            gtestd
            debug
            gmockd
            debug
            gtest_maind
            debug
            gmock_maind
            optimized
            gtest
            optimized
            gmock
            optimized
            gtest_main
            optimized
            gmock_main
            pthread
            fimebpf
            wazuh)

  # Link gcov for coverage when UNIT_TEST is enabled
  if(UNIT_TEST)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      target_link_libraries(${TEST_NAME} PRIVATE -fprofile-arcs)
    else()
      target_link_libraries(${TEST_NAME} PRIVATE gcov)
    endif()
  endif()

  add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})

  set_tests_properties(${TEST_NAME} PROPERTIES LABELS "syscheckd")
endforeach()

cmake_minimum_required(VERSION 3.10)
project(fim_ebpf_whodata_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${SRC_FOLDER}/headers/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(TEST_FILES
    ebpf_whodata_test.cpp
    init_libbpf_test.cpp
    healthcheck_event_test.cpp
    init_ring_buffer_test.cpp
    init_bpf_obj_test.cpp
    close_libbpf_test.cpp
    pop_event_test.cpp)

# Create an executable for each test file
foreach(TEST_FILE ${TEST_FILES})
  get_filename_component(TEST_NAME "${TEST_FILE}" NAME_WE)
  add_executable("${TEST_NAME}" "${TEST_FILE}")
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

  # Link gcov for coverage when UNIT_TEST is enabled (libwazuh.a has coverage symbols)
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

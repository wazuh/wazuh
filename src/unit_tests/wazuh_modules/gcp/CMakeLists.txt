# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Tests list and flags
list(APPEND tests_names "test_wm_gcp")
list(APPEND tests_flags "-Wl,--wrap,wm_exec \
                         -Wl,--wrap,sched_scan_dump,--wrap,sched_scan_get_time_until_next_scan \
                         -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,FOREVER,--wrap,w_get_timestamp \
                         -Wl,--wrap,w_sleep_until,--wrap,isDebug -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}")
list(APPEND use_shared_libs 0)

list(APPEND tests_names "test_wmodules_gcp")
list(APPEND tests_flags "-Wl,--wrap,sched_scan_read,--wrap,realpath,--wrap,__realpath_chk,--wrap,IsFile,--wrap,atexit -Wl,--wrap,wfopen -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}")
list(APPEND use_shared_libs 0)

# Generate wazuh modules library
file(GLOB_RECURSE gcp ../../../build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*.c.o ../../../config/*.o)
list(REMOVE_ITEM gcp ../../../build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main.c.o)

add_library(GCP_O STATIC ${gcp})

set_source_files_properties(
  ${gcp}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  GCP_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(GCP_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


# Compiling tests
list(LENGTH tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    # Use linker groups for Linux/BSD to resolve circular dependencies, macOS doesn't support it
    if(NOT APPLE)
        target_link_libraries(
            ${test_name}
            -Wl,--start-group
            ${WAZUHLIB}
            ${WAZUHEXT}
            GCP_O
            -Wl,--end-group
            -lcmocka
            -ldl
            -fprofile-arcs
            -ftest-coverage
        )
    else()
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            GCP_O
            -lcmocka
            -fprofile-arcs
            -ftest-coverage
        )
    endif()
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(${test_name} ${test_name})
endforeach()

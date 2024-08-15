# Copyright (C) 2023, InfoDefense Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Tests list and flags
list(APPEND tests_names "test_wm_ms_graph")
list(APPEND tests_flags "-Wl,--wrap=_merror -Wl,--wrap=_mtinfo -Wl,--wrap=_mtwarn -Wl,--wrap,_mtdebug1 -Wl,--wrap=_mterror -Wl,--wrap,wurl_http_request \
                        -Wl,--wrap,atexit -Wl,--wrap,time -Wl,--wrap,wm_state_io -Wl,--wrap,StartMQ -Wl,--wrap,gmtime_r -Wl,--wrap,isDebug \
                        -Wl,--wrap,sched_scan_get_time_until_next_scan -Wl,--wrap,is_fim_shutdown -Wl,--wrap,fim_db_teardown -Wl,--wrap,Start_win32_Syscheck \
                        -Wl,--wrap,strftime -Wl,--wrap,_mtdebug2 -Wl,--wrap,wm_sendmsg -Wl,--wrap,strerror -Wl,--wrap,_imp__rsync_initialize \
                        -Wl,--wrap,syscom_dispatch -Wl,--wrap,_imp__dbsync_initialize -Wl,--wrap,w_get_timestamp -Wl,--wrap,os_random -Wl,--wrap,FOREVER")


list(APPEND use_shared_libs 1)

list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.h")
list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.c")

# Generate wazuh modules library
file(GLOB ms_graph ../../../wazuh_modules/*.o)
list(REMOVE_ITEM ms_graph ../../../wazuh_modules/main.o)

add_library(MS_GRAPH_O STATIC ${ms_graph})

set_source_files_properties(
  ${ms_graph}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  MS_GRAPH_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(MS_GRAPH_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

list(LENGTH tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)
    list(GET use_shared_libs ${counter} use_libs)

    if(use_libs EQUAL "1")
      add_executable(${test_name} ${test_name}.c ${shared_libs})
    else ()
      add_executable(${test_name} ${test_name}.c)
    endif()

    if(${TARGET} STREQUAL "server")
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            MS_GRAPH_O
            -lcmocka
            -ldl
            -fprofile-arcs
            -ftest-coverage
        )
    else()
        target_link_libraries(
            ${test_name}
            ${TEST_DEPS}
        )
    endif()
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

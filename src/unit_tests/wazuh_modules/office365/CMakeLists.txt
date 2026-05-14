# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Tests list and flags
list(APPEND tests_names "test_wm_office365")
list(APPEND tests_flags "-Wl,--wrap,access -Wl,--wrap,wurl_http_request \
                        -Wl,--wrap,wurl_free_response -Wl,--wrap,wm_sendmsg -Wl,--wrap,strftime -Wl,--wrap,gmtime_r \
                        -Wl,--wrap,wm_state_io -Wl,--wrap,time -Wl,--wrap,StartMQ -Wl,--wrap,wfopen \
                        -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck \ -Wl,--wrap=is_fim_shutdown \
                        -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown \
                        -Wl,--wrap,fim_sync_push_msg -Wl,--wrap,fim_run_integrity -Wl,--wrap,fim_db_remove_path \
                        -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_transaction_start -Wl,--wrap,fim_db_transaction_deleted_rows \
                        -Wl,--wrap,fim_db_transaction_sync_row -Wl,--wrap,fim_db_file_update -Wl,--wrap,fim_db_file_pattern_search \
                        -Wl,--wrap,fim_db_init ${DEBUG_OP_WRAPPERS} -Wl,--wrap,isDebug")

list(APPEND use_shared_libs 1)

list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.h")
list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.c")

# Generate wazuh modules library
file(GLOB office365 ../../../wazuh_modules/*.o)
list(REMOVE_ITEM office365 ../../../wazuh_modules/main.o)

add_library(OFFICE365_O STATIC ${office365})

set_source_files_properties(
  ${office365}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  OFFICE365_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(OFFICE365_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Compiling tests
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
            OFFICE365_O
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
        if(${TARGET} STREQUAL "winagent")
          target_link_libraries(${test_name} fimdb)
        endif(${TARGET} STREQUAL "winagent")
    endif()

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

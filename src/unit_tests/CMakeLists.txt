# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

set(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../)

include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER})


# Wazuh libraries
find_library(WAZUHLIB NAMES libwazuh.a HINTS "${SRC_FOLDER}")
if(NOT WAZUHLIB)
  message(FATAL_ERROR "libwazuh.a not found! Aborting...")
endif()

find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")
if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext.so not found! Aborting...")
endif()


# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage)


# Enable testing
enable_testing()


# Tests list and flags
list(APPEND tests_names "test_file_op")
list(APPEND tests_flags "-Wl,--wrap,isChroot -Wl,--wrap,mferror -Wl,--wrap,stat -Wl,--wrap,chmod -Wl,--wrap,File_DateofChange -Wl,--wrap,getpid -Wl,--wrap,unlink -Wl,--wrap,_merror -Wl,--wrap,_minfo -Wl,--wrap,_mwarn -Wl,--wrap,fopen")

list(APPEND tests_names "test_integrity_op")
list(APPEND tests_flags " ")

list(APPEND tests_names "test_rbtree_op")
list(APPEND tests_flags " ")

list(APPEND tests_names "test_version_op")
list(APPEND tests_flags "-Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose")

list(APPEND tests_names "test_create_db")
list(APPEND tests_flags "-Wl,--wrap,rbtree_insert -Wl,--wrap,rbtree_get -Wl,--wrap,rbtree_replace -Wl,--wrap,OSHash_Get -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug2 \
                         -Wl,--wrap,OSHash_Add -Wl,--wrap,lstat -Wl,--wrap,fim_send_scan_info -Wl,--wrap,send_syscheck_msg -Wl,--wrap,rbtree_keys -Wl,--wrap,readdir -Wl,--wrap,opendir -Wl,--wrap,closedir \
                         -Wl,--wrap,rbtree_delete -Wl,--wrap,OSHash_Delete -Wl,--wrap,print_rbtree -Wl,--wrap,realtime_adddir -Wl,--wrap,HasFilesystem")

list(APPEND tests_names "test_syscheck_audit")
list(APPEND tests_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,IsSocket -Wl,--wrap,IsFile -Wl,--wrap,IsDir -Wl,--wrap,IsLink -Wl,--wrap,IsFile -Wl,--wrap,audit_restart \
                         -Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,fopen -Wl,--wrap,fwrite -Wl,--wrap,fprintf -Wl,--wrap,fclose -Wl,--wrap,symlink -Wl,--wrap,unlink \
                         -Wl,--wrap,audit_open -Wl,--wrap,audit_get_rule_list -Wl,--wrap,audit_close -Wl,--wrap,mdebug1 -Wl,--wrap,_mwarn -Wl,--wrap,W_Vector_length -Wl,--wrap,search_audit_rule \
                         -Wl,--wrap,audit_add_rule -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,SendMSG -Wl,--wrap,fim_whodata_event \
                         -Wl,--wrap,openproc -Wl,--wrap,readproc -Wl,--wrap,freeproc -Wl,--wrap,closeproc -Wl,--wrap,_mdebug2 -Wl,--wrap,get_user -Wl,--wrap,get_group -Wl,--wrap,realpath")

list(APPEND tests_names "test_seechanges")
list(APPEND tests_flags " ")

list(APPEND tests_names "test_syscom")
list(APPEND tests_flags "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig -Wl,--wrap,getSyscheckInternalOptions -Wl,--wrap,fim_sync_push_msg")

list(APPEND tests_names "test_run_realtime")
list(APPEND tests_flags "-Wl,--wrap,inotify_init -Wl,--wrap,inotify_add_watch -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,read \
                        -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Get -Wl,--wrap,rbtree_insert -Wl,--wrap,_merror -Wl,--wrap,W_Vector_insert_unique")

list(APPEND tests_names "test_syscheck_config")
list(APPEND tests_flags "-Wl,--wrap,_merror")

list(APPEND tests_names "test_syscheck")
list(APPEND tests_flags "-Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_setSize -Wl,--wrap,_mwarn")

list(APPEND tests_names "test_fim_sync")
list(APPEND tests_flags "-Wl,--wrap,rbtree_keys -Wl,--wrap,rbtree_get -Wl,--wrap,fim_send_sync_msg -Wl,--wrap,time -Wl,--wrap,rbtree_range -Wl,--wrap,_mwarn \
                         -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 -Wl,--wrap,queue_push_ex")

list(APPEND tests_names "test_run_check")
list(APPEND tests_flags "-Wl,--wrap,_minfo")

list(APPEND tests_names "test_syscheck_op")
list(APPEND tests_flags "-Wl,--wrap,rmdir_ex -Wl,--wrap,wreaddir -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                         -Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,getpwuid_r -Wl,--wrap,getgrgid \
                         -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,wstr_split \
                         -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP")

list(APPEND tests_names "test_fim_db")
list(APPEND tests_flags "-Wl,--wrap=w_is_file,--wrap=remove,--wrap=sqlite3_open_v2,--wrap=sqlite3_exec,--wrap=_merror \
                         -Wl,--wrap=sqlite3_prepare_v2,--wrap=sqlite3_step,--wrap=sqlite3_finalize,--wrap=sqlite3_close_v2 \
                         -Wl,--wrap=chmod,--wrap=sqlite3_free,--wrap=sqlite3_reset,--wrap=sqlite3_clear_bindings \
                         -Wl,--wrap=sqlite3_errmsg,--wrap=sqlite3_bind_int,--wrap=sqlite3_bind_text,--wrap=sqlite3_column_int \
                         -Wl,--wrap=sqlite3_column_text,--wrap=printf")

list(APPEND tests_names "test_wdb_fim")
list(APPEND tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,cJSON_Parse -Wl,--wrap,wdb_begin2 \
                         -Wl,--wrap,cJSON_Delete -Wl,--wrap,cJSON_GetStringValue -Wl,--wrap,cJSON_IsNumber \
                         -Wl,--wrap,cJSON_IsObject -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text \
                         -Wl,--wrap,sqlite3_bind_int64 -Wl,--wrap,sqlite3_step")

list(APPEND tests_names "test_wdb_parser")
list(APPEND tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn \
                         -Wl,--wrap,wdb_scan_info_get -Wl,--wrap,wdb_fim_update_date_entry -Wl,--wrap,wdb_fim_clean_old_entries \
                         -Wl,--wrap,wdb_scan_info_update -Wl,--wrap,wdb_scan_info_fim_checks_control -Wl,--wrap,wdb_syscheck_load \
                         -Wl,--wrap,wdb_fim_delete -Wl,--wrap,wdb_syscheck_save -Wl,--wrap,wdb_syscheck_save2 \
                         -Wl,--wrap,wdbi_query_checksum -Wl,--wrap,wdbi_query_clear")

list(APPEND tests_names "test_analysisd_syscheck")
list(APPEND tests_flags "-Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result -Wl,--wrap,_merror -Wl,--wrap,_mdebug1")

list(APPEND tests_names "test_wdb_integrity")
list(APPEND tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_errmsg \
                         -Wl,--wrap,EVP_DigestInit_ex -Wl,--wrap,EVP_DigestUpdate -Wl,--wrap,_DigestFinal_ex \
                         -Wl,--wrap,sqlite3_column_text -Wl,--wrap,_mdebug2")

list(APPEND tests_names "test_dbsync")
list(APPEND tests_flags "-Wl,--wrap,_merror -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                         -Wl,--wrap,connect_to_remoted -Wl,--wrap,send_msg_to_agent -Wl,--wrap,wdbc_query_ex \
                         -Wl,--wrap,wdbc_parse_result")

# Config files
configure_file("test_syscheck.conf" "test_syscheck.conf" COPYONLY)


# Generate syscheck library
file(GLOB sysfiles ../syscheckd/*.o)
list(REMOVE_ITEM sysfiles ../syscheckd/main.o)
file(GLOB rootfiles ../rootcheck/*.o)

add_library(SYSCHECK_O STATIC ${sysfiles})
add_library(ROOTCHECK_O STATIC ${rootfiles})

set_source_files_properties(
  ${sysfiles}
  ${rootfiles}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  SYSCHECK_O
  ROOTCHECK_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(SYSCHECK_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


# Generate analysisd library
file(GLOB analysisd_files
  ../analysisd/*.o
  ../analysisd/cdb/*.o
  ../analysisd/decoders/*.o
  ../analysisd/decoders/plugins/*.o)

add_library(ANALYSISD_O STATIC ${analysisd_files})

set_source_files_properties(
  ${analysisd_files}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  ANALYSISD_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(ANALYSISD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


# Compiling tests
list(LENGTH tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        SYSCHECK_O
        ANALYSISD_O
        -lcmocka
        -fprofile-arcs
        -ftest-coverage
    )
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(${test_name} ${test_name})
endforeach()


# Coverage
find_program(LCOV_PATH lcov)
if(NOT LCOV_PATH)
  message(FATAL_ERROR "lcov not found! Aborting...")
endif()

find_program(GCOV_PATH gcov)
if(NOT GCOV_PATH)
  message(FATAL_ERROR "gcov not found! Aborting...")
endif()

find_program(GENHTML_PATH genhtml)
if(NOT GENHTML_PATH)
  message(FATAL_ERROR "genhtml not found! Aborting...")
endif()

add_custom_target(coverage
    # Cleanup lcov
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} -directory ${SRC_FOLDER} --rc lcov_branch_coverage=1 --zerocounters

    # Create baseline to make sure untouched files show up in the report
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -c -i -d ${SRC_FOLDER} --rc lcov_branch_coverage=1 -o coverage.base

    # Run tests
    COMMAND ctest

    # Capturing lcov counters and generating report
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} --directory ${SRC_FOLDER} --capture --rc lcov_branch_coverage=1 --output-file coverage.info

    # Add baseline counters
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -a coverage.base -a coverage.info --rc lcov_branch_coverage=1 --output-file coverage.total
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} --remove coverage.total "*external/*" --rc lcov_branch_coverage=1 --output-file coverage.info.cleaned

    # Generate HTML report
    COMMAND ${GENHTML_PATH} -q --output-directory coverage-report --title "WAZUH unit-tests coverage" --rc lcov_branch_coverage=1 --legend coverage.info.cleaned

    # Clean counters
    COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total coverage.info.cleaned
)

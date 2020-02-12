if(NOT ${TARGET} STREQUAL "winagent")
  # Generate syscheck library
  file(GLOB sysfiles ${SRC_FOLDER}/syscheckd/*.o)
  list(REMOVE_ITEM sysfiles ${SRC_FOLDER}/syscheckd/main.o)
  file(GLOB rootfiles ${SRC_FOLDER}/rootcheck/*.o)

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
    CMAKE_C_COMPILER i686-w64-mingw32-gcc
    CMAKE_C_LINK_EXECUTABLE "CMAKE_C_COMPILER <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>"
    )

  target_link_libraries(SYSCHECK_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)
endif()
# Generate Analysisd tests
list(APPEND syscheckd_tests_names "test_syscom")
list(APPEND syscheckd_tests_flags "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig -Wl,--wrap,getSyscheckInternalOptions -Wl,--wrap,fim_sync_push_msg")

set(CREATE_DB_BASE_FLAGS "-Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug2 \
                          -Wl,--wrap,fim_send_scan_info -Wl,--wrap,send_syscheck_msg -Wl,--wrap,readdir \
                          -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,realtime_adddir -Wl,--wrap,HasFilesystem \
                          -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_get_paths_from_inode -Wl,--wrap,delete_target_file \
                          -Wl,--wrap,fim_db_insert_data -Wl,--wrap,OS_MD5_SHA1_SHA256_File -Wl,--wrap,seechanges_addfile\
                          -Wl,--wrap,fim_db_delete_not_scanned -Wl,--wrap,fim_db_set_all_unscanned \
                          -Wl,--wrap,fim_db_set_scanned -Wl,--wrap,get_user -Wl,--wrap,get_group \
                          -Wl,--wrap,fim_db_remove_path -Wl,--wrap,getDefine_Int -Wl,--wrap,isChroot")

list(APPEND syscheckd_tests_names "test_create_db")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=stat,--wrap=w_get_file_permissions \
                                     -Wl,--wrap=decode_win_permissions")
else()
  list(APPEND syscheckd_tests_flags "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=lstat")
endif()

list(APPEND syscheckd_tests_names "test_syscheck_audit")
list(APPEND syscheckd_tests_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,IsSocket -Wl,--wrap,IsFile -Wl,--wrap,IsDir -Wl,--wrap,IsLink -Wl,--wrap,IsFile -Wl,--wrap,audit_restart \
                       -Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,fopen -Wl,--wrap,fwrite -Wl,--wrap,fprintf -Wl,--wrap,fclose -Wl,--wrap,symlink -Wl,--wrap,unlink \
                       -Wl,--wrap,audit_open -Wl,--wrap,audit_get_rule_list -Wl,--wrap,audit_close -Wl,--wrap,mdebug1 -Wl,--wrap,_mwarn -Wl,--wrap,W_Vector_length -Wl,--wrap,search_audit_rule \
                       -Wl,--wrap,audit_add_rule -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,SendMSG -Wl,--wrap,fim_whodata_event \
                       -Wl,--wrap,openproc -Wl,--wrap,readproc -Wl,--wrap,freeproc -Wl,--wrap,closeproc -Wl,--wrap,_mdebug2 -Wl,--wrap,get_user -Wl,--wrap,get_group -Wl,--wrap,realpath")

list(APPEND syscheckd_tests_names "test_seechanges")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "-Wl,--wrap=getDefine_Int,--wrap=isChroot")
else()
  list(APPEND syscheckd_tests_flags " ")
endif()

set(RUN_REALTIME_BASE_FLAGS "-Wl,--wrap,inotify_init -Wl,--wrap,inotify_add_watch -Wl,--wrap,OSHash_Get_ex \
                             -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,read \
                             -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Get -Wl,--wrap,rbtree_insert -Wl,--wrap,_merror \
                             -Wl,--wrap,W_Vector_insert_unique")

list(APPEND syscheckd_tests_names "test_run_realtime")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=getDefine_Int,--wrap=isChroot")
else()
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS}")
endif()

set(SYSCHECK_CONFIG_BASE_FLAGS "-Wl,--wrap,_merror")

list(APPEND syscheckd_tests_names "test_syscheck_config")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS} -Wl,--wrap=getDefine_Int,--wrap=isChroot")
else()
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS}")
endif()

list(APPEND syscheckd_tests_names "test_syscheck")
list(APPEND syscheckd_tests_flags "-Wl,--wrap,_mwarn -Wl,--wrap,fim_db_init")

list(APPEND syscheckd_tests_names "test_fim_sync")
list(APPEND syscheckd_tests_flags "-Wl,--wrap,fim_send_sync_msg -Wl,--wrap,time -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 \
                      -Wl,--wrap,_merror -Wl,--wrap,_mdebug2 -Wl,--wrap,queue_push_ex -Wl,--wrap,fim_db_get_row_path \
                       -Wl,--wrap,fim_db_get_data_checksum -Wl,--wrap,dbsync_check_msg -Wl,--wrap,fim_send_sync_msg \
                       -Wl,--wrap,fim_db_get_count_range -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_entry_json \
                       -Wl,--wrap,fim_db_data_checksum_range -Wl,--wrap,dbsync_state_msg \
                       -Wl,--wrap,fim_db_sync_path_range")

set(RUN_CHECK_BASE_FLAGS "-Wl,--wrap,_minfo")

list(APPEND syscheckd_tests_names "test_run_check")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=getDefine_Int,--wrap=isChroot")
else()
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS}")
endif()

list(APPEND syscheckd_tests_names "test_fim_db")
list(APPEND syscheckd_tests_flags "-Wl,--wrap=w_is_file,--wrap=remove,--wrap=sqlite3_open_v2,--wrap=sqlite3_exec,--wrap=_merror \
                         -Wl,--wrap=sqlite3_prepare_v2,--wrap=sqlite3_step,--wrap=sqlite3_finalize,--wrap=sqlite3_close_v2 \
                         -Wl,--wrap=chmod,--wrap=sqlite3_free,--wrap=sqlite3_reset,--wrap=sqlite3_clear_bindings \
                         -Wl,--wrap=sqlite3_errmsg,--wrap=sqlite3_bind_int,--wrap=sqlite3_bind_text,--wrap=sqlite3_column_int \
                         -Wl,--wrap=sqlite3_column_text,--wrap=printf,--wrap=fim_send_sync_msg,--wrap=dbsync_state_msg \
                         -Wl,--wrap=fim_entry_json")


# Compiling tests
list(LENGTH syscheckd_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET syscheckd_tests_names ${counter} test_name)
    list(GET syscheckd_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    if(NOT ${TARGET} STREQUAL "winagent")
      target_link_libraries(
        ${test_name}
        SYSCHECK_O
        ${TEST_DEPS}
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

# Generate syscheck library
file(GLOB sysfiles ${SRC_FOLDER}/syscheckd/*.o)
list(REMOVE_ITEM sysfiles ${SRC_FOLDER}/syscheckd/main.o)

file(GLOB rootfiles ${SRC_FOLDER}/rootcheck/*.o)

if(${TARGET} STREQUAL "winagent")
  # Exclude winagent files
  list(FILTER sysfiles EXCLUDE REGEX ".*-event.o$")
  list(FILTER rootfiles EXCLUDE REGEX ".*_rk.o$")

  # Add test wrappers
  file(GLOB test_wrapper_files
       ${SRC_FOLDER}/unit_tests/wrappers/externals/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/audit/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/bzip2/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/cJSON/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/openssl/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/procpc/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/sqlite/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/libc/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/linux/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/posix/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_crypto/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_net/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_regex/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/syscheckd/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/wazuh_db/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/wazuh_modules/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/windows/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/windows/libc/*.o
       )
  list(APPEND sysfiles ${test_wrapper_files})
endif()

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

# Generate syscheckd-event library
if(${TARGET} STREQUAL "winagent")
  file(GLOB syscheck_event_files ${SRC_FOLDER}/syscheckd/*-event.o)

  add_library(SYSCHECK_EVENT_O STATIC ${syscheck_event_files})

  set_source_files_properties(
    ${syscheck_event_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
    )

  set_target_properties(
    SYSCHECK_EVENT_O
    ROOTCHECK_O
    PROPERTIES
    LINKER_LANGUAGE C
    )

  target_link_libraries(SYSCHECK_EVENT_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)
endif()

# Generate Syscheckd tests
list(APPEND syscheckd_tests_names "test_syscom")
list(APPEND syscheckd_tests_flags "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig \
                                   -Wl,--wrap,getSyscheckInternalOptions -Wl,--wrap,fim_sync_push_msg \
                                   -Wl,--wrap,_mdebug1")

set(CREATE_DB_BASE_FLAGS "-Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 \
                          -Wl,--wrap,_mdebug2 -Wl,--wrap,fim_send_scan_info -Wl,--wrap,send_syscheck_msg \
                          -Wl,--wrap,readdir -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,realtime_adddir \
                          -Wl,--wrap,HasFilesystem -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_get_paths_from_inode \
                          -Wl,--wrap,delete_target_file -Wl,--wrap,fim_db_insert -Wl,--wrap,OS_MD5_SHA1_SHA256_File \
                          -Wl,--wrap,seechanges_addfile -Wl,--wrap,fim_db_delete_not_scanned \
                          -Wl,--wrap,fim_db_set_all_unscanned -Wl,--wrap,fim_db_set_scanned -Wl,--wrap,get_user \
                          -Wl,--wrap,get_group -Wl,--wrap,fim_db_remove_path -Wl,--wrap,isChroot \
                          -Wl,--wrap,fim_db_get_not_scanned -Wl,--wrap,fim_db_set_all_unscanned \
                          -Wl,--wrap,fim_db_get_count_entry_path -Wl,--wrap,fim_db_get_path_range \
                          -Wl,--wrap,fim_db_process_missing_entry -Wl,--wrap,send_log_msg -Wl,--wrap,IsDir \
                          -Wl,--wrap,DirSize -Wl,--wrap,seechanges_get_diff_path -Wl,--wrap,stat")

list(APPEND syscheckd_tests_names "test_create_db")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=w_get_file_permissions \
                                     -Wl,--wrap=decode_win_permissions,--wrap=pthread_mutex_lock \
                                     -Wl,--wrap=pthread_mutex_unlock,--wrap=w_get_file_attrs,--wrap=os_winreg_check")
else()
  list(APPEND syscheckd_tests_flags "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=lstat -Wl,--wrap=count_watches")
endif()

if(NOT ${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_names "test_syscheck_audit")
  list(APPEND syscheckd_tests_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,fprintf -Wl,--wrap,IsSocket -Wl,--wrap,select \
                                     -Wl,--wrap,IsFile -Wl,--wrap,IsDir -Wl,--wrap,IsLink -Wl,--wrap,audit_delete_rule \
                                     -Wl,--wrap,audit_restart -Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,fopen \
                                     -Wl,--wrap,fclose -Wl,--wrap,symlink -Wl,--wrap,unlink -Wl,--wrap,fwrite \
                                     -Wl,--wrap,audit_open -Wl,--wrap,audit_get_rule_list -Wl,--wrap,audit_close \
                                     -Wl,--wrap,_mdebug1 -Wl,--wrap,_mwarn -Wl,--wrap,W_Vector_length \
                                     -Wl,--wrap,search_audit_rule -Wl,--wrap,audit_add_rule -Wl,--wrap,recv \
                                     -Wl,--wrap,pthread_cond_init -Wl,--wrap,pthread_cond_wait -Wl,--wrap,pthread_mutex_lock \
                                     -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,CreateThread -Wl,--wrap,sleep \
                                     -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,SendMSG -Wl,--wrap,audit_delete_rule \
                                     -Wl,--wrap,fim_whodata_event -Wl,--wrap,fflush -Wl,--wrap,fgets \
                                     -Wl,--wrap,openproc -Wl,--wrap,readproc -Wl,--wrap,freeproc \
                                     -Wl,--wrap,closeproc -Wl,--wrap,_mdebug2 -Wl,--wrap,get_user \
                                     -Wl,--wrap,get_group -Wl,--wrap,realpath -Wl,--wrap,readlink -Wl,--wrap,fread \
                                     -Wl,--wrap,fseek -Wl,--wrap,remove -Wl,--wrap,atexit -Wl,--wrap,getpid -Wl,--wrap,FOREVER")
endif()

set(SEECHANGES_BASE_FLAGS "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,lstat -Wl,--wrap,stat -Wl,--wrap,abspath \
                           -Wl,--wrap,wfopen -Wl,--wrap,fread -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fwrite \
                           -Wl,--wrap,w_compress_gzfile -Wl,--wrap,IsDir -Wl,--wrap,mkdir -Wl,--wrap,fflush \
                           -Wl,--wrap,w_uncompress_gzfile -Wl,--wrap,OS_MD5_File -Wl,--wrap,File_DateofChange \
                           -Wl,--wrap,rename -Wl,--wrap,system -Wl,--wrap,fseek -Wl,--wrap,remove,--wrap=fprintf \
                           -Wl,--wrap=fgets -Wl,--wrap,atexit -Wl,--wrap,getpid,--wrap=_mdebug2,--wrap=rmdir_ex,--wrap=rename_ex \
                           -Wl,--wrap,_minfo,--wrap=DirSize")

list(APPEND syscheckd_tests_names "test_seechanges")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${SEECHANGES_BASE_FLAGS} -Wl,--wrap=isChroot,--wrap=unlink -Wl,--wrap=FileSize")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${SEECHANGES_BASE_FLAGS} -Wl,--wrap=_unlink,--wrap=FileSizeWin")
else()
  list(APPEND syscheckd_tests_flags "${SEECHANGES_BASE_FLAGS} -Wl,--wrap=unlink,--wrap=FileSize")
endif()

set(RUN_REALTIME_BASE_FLAGS "-Wl,--wrap,inotify_init -Wl,--wrap,inotify_add_watch -Wl,--wrap,OSHash_Get_ex \
                             -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,read \
                             -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Get -Wl,--wrap,rbtree_insert \
                             -Wl,--wrap,_merror -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,_mwarn \
                             -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 -Wl,--wrap,_merror_exit -Wl,--wrap,send_log_msg \
                             -Wl,--wrap,rbtree_keys -Wl,--wrap,fim_realtime_event -Wl,--wrap,OSHash_Delete_ex \
                             -Wl,--wrap=OSHash_Begin -Wl,--wrap=OSHash_Next -Wl,--wrap=pthread_mutex_lock \
                             -Wl,--wrap=pthread_mutex_unlock -Wl,--wrap=getpid -Wl,--wrap=atexit -Wl,--wrap=os_random \
                             -Wl,--wrap,inotify_rm_watch")

list(APPEND syscheckd_tests_names "test_run_realtime")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=isChroot")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=fim_configuration_directory")

  # Create event channel tests for run_realtime
  list(APPEND syscheckd_event_tests_names "test_run_realtime_event")
  list(APPEND syscheckd_event_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=whodata_audit_start \
                                           -Wl,--wrap=check_path_type,--wrap=set_winsacl,--wrap=w_directory_exists")
else()
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS}")
endif()

set(SYSCHECK_CONFIG_BASE_FLAGS "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,_mwarn")

list(APPEND syscheckd_tests_names "test_syscheck_config")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS} -Wl,--wrap=isChroot")
else()
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS}")
endif()

set(SYSCHECK_BASE_FLAGS "-Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_merror_exit \
                         -Wl,--wrap,_minfo -Wl,--wrap,fim_db_init -Wl,--wrap,getDefine_Int")
list(APPEND syscheckd_tests_names "test_syscheck")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_BASE_FLAGS} \
                                    -Wl,--wrap=Read_Syscheck_Config \
                                    -Wl,--wrap=os_wait \
                                    -Wl,--wrap=rootcheck_init \
                                    -Wl,--wrap=start_daemon \
                                    -Wl,--wrap=File_DateofChange")

else()
  list(APPEND syscheckd_tests_flags "${SYSCHECK_BASE_FLAGS}")
endif()

set(FIM_SYNC_BASE_FLAGS "-Wl,--wrap,fim_send_sync_msg -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 \
                         -Wl,--wrap,_merror -Wl,--wrap,_mdebug2 -Wl,--wrap,queue_push_ex \
                         -Wl,--wrap,fim_db_get_row_path -Wl,--wrap,fim_db_get_data_checksum \
                         -Wl,--wrap,dbsync_check_msg -Wl,--wrap,fim_send_sync_msg -Wl,--wrap,fim_db_get_count_range \
                         -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_entry_json -Wl,--wrap,fim_db_data_checksum_range \
                         -Wl,--wrap,dbsync_state_msg -Wl,--wrap,fim_db_sync_path_range \
                         -Wl,--wrap,fim_db_get_path_range")

list(APPEND syscheckd_tests_names "test_fim_sync")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${FIM_SYNC_BASE_FLAGS} -Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock")
else()
  list(APPEND syscheckd_tests_flags "${FIM_SYNC_BASE_FLAGS} -Wl,--wrap,time")
endif()

set(RUN_CHECK_BASE_FLAGS "-Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                          -Wl,--wrap,_merror_exit -Wl,--wrap,sleep -Wl,--wrap,SendMSG -Wl,--wrap,StartMQ \
                          -Wl,--wrap,realtime_adddir -Wl,--wrap,audit_set_db_consistency -Wl,--wrap,fim_checker \
                          -Wl,--wrap,fim_db_get_path_range -Wl,--wrap,fim_db_delete_range -Wl,--wrap,lstat \
                          -Wl,--wrap,fim_configuration_directory -Wl,--wrap,inotify_rm_watch -Wl,--wrap,os_random \
                          -Wl,--wrap,stat -Wl,--wrap,getpid")

list(APPEND syscheckd_tests_names "test_run_check")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=isChroot,--wrap=sleep -Wl,--wrap,time")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=realtime_start")

  # Create event channel tests for run_check
  list(APPEND syscheckd_event_tests_names "test_run_check_event")
  list(APPEND syscheckd_event_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=realtime_start,--wrap=run_whodata_scan \
                                                                    -Wl,--wrap=audit_restore")
else()
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=sleep,--wrap,time")
endif()

set(FIM_DB_BASE_FLAGS "-Wl,--wrap=w_is_file,--wrap=remove,--wrap=sqlite3_open_v2,--wrap=sqlite3_exec,--wrap=_merror \
                       -Wl,--wrap=sqlite3_prepare_v2,--wrap=sqlite3_step,--wrap=sqlite3_finalize \
                       -Wl,--wrap=sqlite3_close_v2 -Wl,--wrap=chmod,--wrap=sqlite3_free,--wrap=sqlite3_reset \
                       -Wl,--wrap=sqlite3_clear_bindings -Wl,--wrap=sqlite3_errmsg,--wrap=sqlite3_bind_int \
                       -Wl,--wrap=sqlite3_bind_text,--wrap=sqlite3_column_int -Wl,--wrap=sqlite3_column_text \
                       -Wl,--wrap=fim_send_sync_msg,--wrap=dbsync_state_msg -Wl,--wrap=fim_entry_json \
                       -Wl,--wrap=sqlite3_last_insert_rowid,--wrap=EVP_DigestUpdate \
                       -Wl,--wrap=fim_configuration_directory,--wrap=fim_json_event,--wrap=send_syscheck_msg \
                       -Wl,--wrap=delete_target_file,--wrap=_minfo,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap=fseek \
                       -Wl,--wrap=fclose,--wrap=fopen,--wrap=getpid,--wrap=fflush -Wl,--wrap=wstr_escape_json \
                       -Wl,--wrap=sqlite3_bind_int64,--wrap=sqlite3_column_int64 -Wl,--wrap=fread,--wrap=fwrite \
                       -Wl,--wrap=fprintf,--wrap=fgets,--wrap=stat,--wrap=wstr_split,--wrap=os_random \
                       -Wl,--wrap=DirSize,--wrap=IsDir")

list(APPEND syscheckd_tests_names "test_fim_db")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${FIM_DB_BASE_FLAGS} -Wl,--wrap=isChroot -Wl,--wrap=usleep,--wrap=time")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${FIM_DB_BASE_FLAGS}")
else()
list(APPEND syscheckd_tests_flags "${FIM_DB_BASE_FLAGS} -Wl,--wrap=usleep,--wrap=time")
endif()

if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_names "test_win_registry")
  list(APPEND syscheckd_tests_flags "-Wl,--wrap=_mdebug2,--wrap=fim_registry_event,--wrap=EVP_DigestUpdate \
                                     -Wl,--wrap=_mdebug1 -Wl,--wrap=_mwarn")

  list(APPEND syscheckd_event_tests_names "test_win_whodata")
  list(APPEND syscheckd_event_tests_flags "-Wl,--wrap=_mdebug2,--wrap=_merror,--wrap=_mdebug1,--wrap=_mwarn \
                                           -Wl,--wrap=wstr_replace -Wl,--wrap=SendMSG,--wrap,OSHash_Add_ex \
                                           -Wl,--wrap=free_whodata_event,--wrap=IsFile -Wl,--wrap=remove \
                                           -Wl,--wrap=wm_exec,--wrap=fopen,--wrap=fclose,--wrap=atexit \
                                           -Wl,--wrap=OSHash_Delete_ex,--wrap=_mterror,--wrap=check_path_type \
                                           -Wl,--wrap=_minfo -Wl,--wrap=OSHash_Create -Wl,--wrap=pthread_rwlock_unlock\
                                           -Wl,--wrap=OSHash_SetFreeDataPointer,--wrap=fim_whodata_event \
                                           -Wl,--wrap=fim_checker,--wrap=OSHash_Get,--wrap=os_random \
                                           -Wl,--wrap=convert_windows_string,--wrap=OSHash_Get_ex,--wrap=FOREVER \
                                           -Wl,--wrap=fflush,--wrap=fread,--wrap=fseek,--wrap=fwrite,--wrap=fprintf \
                                           -Wl,--wrap=fgets -Wl,--wrap=wstr_split -Wl,--wrap=pthread_rwlock_wrlock")
endif()

# Compiling tests
list(LENGTH syscheckd_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET syscheckd_tests_names ${counter} test_name)
    list(GET syscheckd_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
      ${test_name}
      SYSCHECK_O
      ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

if(${TARGET} STREQUAL "winagent")
  # Compile event channel tests
  list(LENGTH syscheckd_event_tests_names count)
  math(EXPR count "${count} - 1")
  foreach(counter RANGE ${count})
      list(GET syscheckd_event_tests_names ${counter} test_name)
      list(GET syscheckd_event_tests_flags ${counter} test_flags)

      string(REPLACE "_event" ".c" test_file ${test_name})
      add_executable(${test_name} ${test_file})

      target_link_libraries(
        ${test_name}
        SYSCHECK_EVENT_O
        ${TEST_EVENT_DEPS}
      )

      target_compile_definitions(${test_name} PUBLIC WIN_WHODATA)

      if(NOT test_flags STREQUAL " ")
          target_link_libraries(
              ${test_name}
              ${test_flags}
          )
      endif()
      add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()

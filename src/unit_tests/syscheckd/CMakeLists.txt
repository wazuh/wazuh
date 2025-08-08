# Generate syscheck library
if(${TARGET} STREQUAL "winagent")
  file(GLOB sysfiles ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd-event.dir/src/*.obj
                     ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd-event.dir/src/*/*.obj)
  list(REMOVE_ITEM sysfiles ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd.dir/src/main.c.obj)
else()
  file(GLOB sysfiles ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd.dir/src/*.o
                     ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd.dir/src/*/*.o)
  list(REMOVE_ITEM sysfiles ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd.dir/src/main.c.o)
endif()

file(GLOB rootfiles ${SRC_FOLDER}/rootcheck/*.o)
list(APPEND rootfiles ${SRC_FOLDER}/shared/fs_op.o)

if(${TARGET} STREQUAL "winagent")
  # Exclude winagent file
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
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/sync_protocol/*.o
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

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Add fim_tools library to compilation
include_directories(${SRC_FOLDER}/syscheckd/include)
include_directories(${SRC_FOLDER}/syscheckd/src)
include_directories(${SRC_FOLDER}/unit_tests)
include_directories(${SRC_FOLDER}/unit_tests/syscheckd)
include_directories(${SRC_FOLDER}/config)

add_library(fim_shared STATIC expect_run_check.c
                              expect_fim_diff_changes.c
                              utils.c)

set_target_properties(fim_shared PROPERTIES LINKER_LANGUAGE C )


#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate syscheckd-event library
if(${TARGET} STREQUAL "winagent")
  file(GLOB syscheck_event_files ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd-event.dir/src/*.obj
                                 ${SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd-event.dir/src/*/*.obj)
  list(REMOVE_ITEM sysfiles {SRC_FOLDER}/syscheckd/build/CMakeFiles/wazuh-syscheckd-event.dir/src/main.obj)
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

  add_subdirectory(registry)
endif()

add_subdirectory(whodata)

# Generate Syscheckd tests
# syscom.c tests
list(APPEND syscheckd_tests_names "syscom")
set(FIM_SYSCOM_BASE_FLAGS "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig -Wl,--wrap,getSyscheckInternalOptions \
                           -Wl,--wrap,getpid -Wl,--wrap,fim_sync_push_msg -Wl,--wrap,fim_db_init -Wl,--wrap,fim_db_transaction_sync_row \
                           -Wl,--wrap,fim_db_file_pattern_search -Wl,--wrap,fim_db_transaction_deleted_rows \
                           -Wl,--wrap,fim_db_get_count_file_entry -Wl,--wrap,fim_db_get_count_file_inode -Wl,--wrap,fim_db_file_inode_search \
                           -Wl,--wrap,fim_db_file_update -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_transaction_start \
                           -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                           ${DEBUG_OP_WRAPPERS}")

if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${FIM_SYSCOM_BASE_FLAGS} -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=fim_db_init -Wl,--wrap,fim_sync_push_msg \
                                     -Wl,--wrap=fim_db_get_count_registry_data -Wl,--wrap=fim_db_get_count_registry_key \
                                     -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                                     -Wl,--wrap=fim_db_file_pattern_search -Wl,--wrap=fim_db_transaction_start \
                                     -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_transaction_deleted_rows \
                                     -Wl,--wrap=fim_db_file_update -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=is_fim_shutdown \
                                     -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
  list(APPEND syscheckd_tests_flags "${FIM_SYSCOM_BASE_FLAGS}")
endif()

# fim_diff_changes.c tests
set(FIM_DIFF_CHANGES_BASE_FLAGS "-Wl,--wrap,lstat -Wl,--wrap,stat \
                                 -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fclose -Wl,--wrap,fwrite -Wl,--wrap,wfopen \
                                 -Wl,--wrap,w_compress_gzfile -Wl,--wrap,IsDir -Wl,--wrap,mkdir_ex -Wl,--wrap,fflush \
                                 -Wl,--wrap,w_uncompress_gzfile -Wl,--wrap,OS_MD5_File -Wl,--wrap,File_DateofChange \
                                 -Wl,--wrap,rename -Wl,--wrap,system -Wl,--wrap,fseek -Wl,--wrap,remove,--wrap=fprintf \
                                 -Wl,--wrap=fgets -Wl,--wrap,atexit -Wl,--wrap,getpid,--wrap=_mdebug2,--wrap=rmdir_ex,--wrap=rename_ex \
                                 -Wl,--wrap=DirSize,--wrap=remove_empty_folders,--wrap=abspath,--wrap=getpid \
                                 -Wl,--wrap,fgetpos -Wl,--wrap=fgetc -Wl,--wrap=pthread_rwlock_wrlock -Wl,--wrap=pthread_mutex_lock \
                                 -Wl,--wrap=pthread_mutex_unlock -Wl,--wrap=pthread_rwlock_unlock -Wl,--wrap=pthread_rwlock_rdlock \
                                 -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                                 -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                                 -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_init -Wl,--wrap=fim_run_integrity \
                                 -Wl,--wrap=fim_db_transaction_start -Wl,--wrap=fim_db_transaction_sync_row \
                                 -Wl,--wrap=fim_db_transaction_deleted_rows -Wl,--wrap,popen \
                                 -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                                 ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "fim_diff_changes")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${FIM_DIFF_CHANGES_BASE_FLAGS} -Wl,--wrap=FileSizeWin -Wl,--wrap,fim_sync_push_msg \
                                     -Wl,--wrap=fim_db_get_count_registry_data -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                     -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                     -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown -Wl,--wrap=utf8_GetShortPathName")
else()
  list(APPEND syscheckd_tests_flags "${FIM_DIFF_CHANGES_BASE_FLAGS} -Wl,--wrap=unlink -Wl,--wrap=FileSize")
endif()

# run_realtime.c tests
set(RUN_REALTIME_BASE_FLAGS "-Wl,--wrap,inotify_init -Wl,--wrap,inotify_add_watch -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_file_pattern_search \
                             -Wl,--wrap,read -Wl,--wrap,rbtree_insert -Wl,--wrap,fim_db_init -Wl,--wrap,fim_db_file_update \
                             -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,send_log_msg  -Wl,--wrap,fim_db_remove_path \
                             -Wl,--wrap,rbtree_keys -Wl,--wrap,fim_realtime_event -Wl,--wrap=pthread_mutex_lock -Wl,--wrap,wfopen \
                             -Wl,--wrap=pthread_mutex_unlock -Wl,--wrap=getpid -Wl,--wrap=atexit -Wl,--wrap=os_random \
                             -Wl,--wrap,inotify_rm_watch -Wl,--wrap,pthread_rwlock_wrlock -Wl,--wrap,pthread_rwlock_unlock \
                             -Wl,--wrap,fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode -Wl,--wrap,fim_db_get_count_file_entry \
                             -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                             -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                             -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                             ${HASH_OP_WRAPPERS} ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "run_realtime")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=fim_configuration_directory -Wl,--wrap,fim_sync_push_msg \
                                     -Wl,--wrap=fim_db_get_count_registry_data -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                     -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                     -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")

  # Create event channel tests for run_realtime
  list(APPEND syscheckd_event_tests_names "test_run_realtime_event")
  list(APPEND syscheckd_event_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=whodata_audit_start -Wl,--wrap=win_strerror \
                                           -Wl,--wrap=check_path_type,--wrap=set_winsacl,--wrap=w_directory_exists \
                                           -Wl,--wrap,fim_sync_push_msg -Wl,--wrap=fim_db_get_count_registry_data \
                                           -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch
                                           -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                           -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown \
                                           -Wl,--wrap=utf8_CreateFile")
else()
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS}")
endif()

# syscheck_config.c tests
set(SYSCHECK_CONFIG_BASE_FLAGS "-Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,pthread_rwlock_unlock \
                                -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_rwlock_wrlock \
                                -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,fim_db_init \
                                -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                                -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                                -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                                -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                                -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                                ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "config")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS}")
else()
  if(${TARGET} STREQUAL "winagent")
    list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS} -Wl,--wrap,fim_sync_push_msg \
                                      -Wl,--wrap=fim_db_get_count_registry_data \
                                      -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                      -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                      -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
  else()
    list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS} -Wl,--wrap,getpid")
  endif()
endif()

# syscheck.c tests
set(SYSCHECK_BASE_FLAGS "-Wl,--wrap,fim_db_init -Wl,--wrap,getDefine_Int -Wl,--wrap,wfopen \
                         -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                         -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                         -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                         -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                         -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                         ${DEBUG_OP_WRAPPERS}")
list(APPEND syscheckd_tests_names "syscheck")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_BASE_FLAGS} \
                                    -Wl,--wrap=Read_Syscheck_Config \
                                    -Wl,--wrap=rootcheck_init \
                                    -Wl,--wrap=start_daemon \
                                    -Wl,--wrap=File_DateofChange \
                                    -Wl,--wrap,getpid,--wrap,realtime_start \
                                    -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,pthread_rwlock_unlock \
                                    -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_rwlock_wrlock \
                                    -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,fim_sync_push_msg \
                                    -Wl,--wrap=fim_db_get_count_registry_data \
                                    -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                    -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                    -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")

else()
  list(APPEND syscheckd_tests_flags "${SYSCHECK_BASE_FLAGS}")
endif()

# run_check.c tests
set(RUN_CHECK_BASE_FLAGS "-Wl,--wrap,sleep -Wl,--wrap,SendMSGPredicated -Wl,--wrap,StartMQ \
                          -Wl,--wrap,realtime_adddir -Wl,--wrap,audit_set_db_consistency -Wl,--wrap,fim_checker \
                          -Wl,--wrap,lstat -Wl,--wrap,fim_db_file_pattern_search \
                          -Wl,--wrap,fim_configuration_directory -Wl,--wrap,inotify_rm_watch -Wl,--wrap,os_random \
                          -Wl,--wrap,stat -Wl,--wrap,getpid -Wl,--wrap,gettime \
                          -Wl,--wrap,remove_audit_rule_syscheck -Wl,--wrap,realtime_process -Wl,--wrap,FOREVER \
                          -Wl,--wrap,select -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                          -Wl,--wrap=fim_db_init,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                          -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                          -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                          -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                          -Wl,--wrap=fim_generate_delete_event -Wl,--wrap=asp_sync_module \
                          -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                          ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "run_check")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=sleep -Wl,--wrap,time")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=realtime_start \
                                     -Wl,--wrap,WaitForSingleObjectEx -Wl,--wrap,pthread_rwlock_rdlock \
                                     -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,pthread_rwlock_wrlock \
                                     -Wl,--wrap,fim_sync_push_msg -Wl,--wrap=fim_db_get_count_registry_data \
                                     -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                     -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                     -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")

  # Create event channel tests for run_check
  list(APPEND syscheckd_event_tests_names "test_run_check_event")
  list(APPEND syscheckd_event_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=realtime_start,--wrap=run_whodata_scan \
                                                                   -Wl,--wrap=audit_restore
                                                                   -Wl,--wrap,pthread_rwlock_rdlock \
                                                                   -Wl,--wrap,pthread_rwlock_unlock \
                                                                   -Wl,--wrap,pthread_mutex_lock \
                                                                   -Wl,--wrap,pthread_rwlock_wrlock \
                                                                   -Wl,--wrap,pthread_mutex_unlock \
                                                                   -Wl,--wrap,fim_sync_push_msg \
                                                                   -Wl,--wrap=fim_db_get_count_registry_data \
                                                                   -Wl,--wrap=fim_db_get_count_registry_key \
                                                                   -Wl,--wrap=syscom_dispatch \
                                                                   -Wl,--wrap=fim_generate_delete_event \
                                                                   -Wl,--wrap=is_fim_shutdown \
                                                                   -Wl,--wrap=_imp__dbsync_initialize \
                                                                   -Wl,--wrap=_imp__rsync_initialize \
                                                                   -Wl,--wrap=fim_db_teardown")
else()
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=sleep,--wrap,time")
endif()

# Compiling tests
list(LENGTH syscheckd_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET syscheckd_tests_names ${counter} test_name)
    list(GET syscheckd_tests_flags ${counter} test_flags)

    add_executable(test_${test_name} test_${test_name}.c)
    target_link_libraries(
      test_${test_name}
      SYSCHECK_O
      ${TEST_DEPS}
    )

    if(${TARGET} STREQUAL "winagent")
      target_link_libraries(test_${test_name} fimdb)
    endif(${TARGET} STREQUAL "winagent")

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            test_${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME test_${test_name} COMMAND test_${test_name})
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
        fimdb
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

# fim_scan.c tests
add_executable(test_fim_scan test_fim_scan.c)

target_compile_options(test_fim_scan PRIVATE "-Wall")

set(CREATE_DB_BASE_FLAGS "-Wl,--wrap,send_syscheck_msg -Wl,--wrap,persist_syscheck_msg \
                          -Wl,--wrap,readdir -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,realtime_adddir \
                          -Wl,--wrap,HasFilesystem -Wl,--wrap,fim_db_get_path \
                          -Wl,--wrap,delete_target_file -Wl,--wrap,OS_MD5_SHA1_SHA256_File \
                          -Wl,--wrap,seechanges_addfile -Wl,--wrap,fim_db_delete_not_scanned \
                          -Wl,--wrap,get_group,--wrap,mdebug2 -Wl,--wrap,wfopen \
                          -Wl,--wrap,send_log_msg -Wl,--wrap,IsDir \
                          -Wl,--wrap,DirSize -Wl,--wrap,seechanges_get_diff_path -Wl,--wrap,stat \
                          -Wl,--wrap,fim_file_diff -Wl,--wrap,fim_diff_process_delete_file \
                          -Wl,--wrap,fim_db_get_count_entries \
                          -Wl,--wrap,fim_db_file_is_scanned -Wl,--wrap,fim_db_data_exists \
                          -Wl,--wrap,fim_db_append_paths_from_inode -Wl,--wrap,pthread_rwlock_wrlock \
                          -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,pthread_rwlock_rdlock \
                          -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                          -Wl,--wrap,expand_wildcards -Wl,--wrap,fim_add_inotify_watch \
                          -Wl,--wrap,realtime_sanitize_watch_map,--wrap=fim_db_remove_path \
                          -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_init \
                          -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                          -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                          -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                          -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                          ${DEBUG_OP_WRAPPERS}")

target_link_libraries(test_fim_scan SYSCHECK_O ${TEST_DEPS} fim_shared)
if(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_fim_scan "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=w_get_file_permissions
                                          -Wl,--wrap,getpid -Wl,--wrap=fim_db_get_count_registry_data \
                                          -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                          -Wl,--wrap=decode_win_acl_json,--wrap=w_get_file_attrs -Wl,--wrap=os_winreg_check \
                                          -Wl,--wrap,get_file_user -Wl,--wrap,fim_registry_scan \
                                          -Wl,--wrap,get_UTC_modification_time -Wl,--wrap,fim_sync_push_msg \
                                          -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                          -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown \
                                          -Wl,--wrap=utf8_stat64"
                                          fimdb)
else()
    target_link_libraries(test_fim_scan "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=lstat -Wl,--wrap=count_watches \
                                          -Wl,--wrap,get_user -Wl,--wrap,realpath -Wl,--wrap,add_whodata_directory \
                                          -Wl,--wrap,atexit -Wl,--wrap,remove_audit_rule_syscheck")
endif()

add_test(NAME test_fim_scan COMMAND test_fim_scan)

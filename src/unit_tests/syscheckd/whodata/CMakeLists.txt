include_directories(${SRC_FOLDER}/syscheckd/include)
include_directories(${SRC_FOLDER}/syscheckd/src)
include_directories(${SRC_FOLDER}/unit_tests)
include_directories(${SRC_FOLDER}/config)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

if(NOT ${TARGET} STREQUAL "winagent")
    # test_audit_healthcheck tests
    add_executable(test_audit_healthcheck test_audit_healthcheck.c)
    target_compile_options(test_audit_healthcheck PRIVATE "-Wall")

    set(AUDIT_HC_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap,audit_add_rule \
                        -Wl,--wrap,pthread_cond_wait -Wl,--wrap,pthread_mutex_lock \
                        -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,CreateThread -Wl,--wrap,wfopen \
                        -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fgetpos \
                        -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc \
                        -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink -Wl,--wrap,audit_delete_rule \
                        -Wl,--wrap,select -Wl,--wrap,audit_parse -Wl,--wrap=abspath -Wl,--wrap,atomic_int_get \
                        -Wl,--wrap,atomic_int_set -Wl,--wrap,atomic_int_dec -Wl,--wrap,atomic_int_inc \
                        -Wl,--wrap,pthread_cond_timedwait -Wl,--wrap,gettime -Wl,--wrap,fim_db_init \
                        -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                        -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                        -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                        -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows -Wl,--wrap,popen")

    target_link_libraries(test_audit_healthcheck SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_healthcheck "${AUDIT_HC_FLAGS}")
    add_test(NAME test_audit_healthcheck COMMAND test_audit_healthcheck)

    # test_syscheck_rule_handling tests
    add_executable(test_audit_rule_handling test_audit_rule_handling.c)
    target_compile_options(test_audit_rule_handling PRIVATE "-Wall")

    set(SYSCHECK_AUDIT_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2,--wrap=_merror,--wrap=_mwarn,--wrap=audit_add_rule\
                              -Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock,--wrap=fim_db_init \
                              -Wl,--wrap=pthread_rwlock_rdlock,--wrap=pthread_rwlock_wrlock,--wrap=pthread_rwlock_unlock \
                              -Wl,--wrap=fopen,--wrap=fclose,--wrap=fflush,--wrap=fgets,--wrap=fgetpos,--wrap=wfopen \
                              -Wl,--wrap=fread,--wrap=fseek,--wrap=fwrite,--wrap=remove,--wrap=fgetc \
                              -Wl,--wrap=getpid,--wrap=sleep,--wrap=unlink,--wrap=audit_delete_rule \
                              -Wl,--wrap=select,--wrap=audit_parse,--wrap=audit_get_rule_list,--wrap=audit_close \
                              -Wl,--wrap=search_audit_rule,--wrap=audit_open -Wl,--wrap,atomic_int_get \
                              -Wl,--wrap,atomic_int_set -Wl,--wrap,atomic_int_dec -Wl,--wrap,atomic_int_inc \
                              -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                              -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                              -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                              -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows -Wl,--wrap,popen")

    target_link_libraries(test_audit_rule_handling SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_rule_handling "${SYSCHECK_AUDIT_FLAGS}")
    add_test(NAME test_audit_rule_handling COMMAND test_audit_rule_handling)

    # test_syscheck_audit tests
    add_executable(test_syscheck_audit test_syscheck_audit.c)
    target_compile_options(test_syscheck_audit PRIVATE "-Wall")

    set(SYSCHECK_AUDIT_FLAGS "-Wl,--wrap,pthread_cond_wait -Wl,--wrap,pthread_mutex_lock \
                              -Wl,--wrap,openproc -Wl,--wrap,readproc -Wl,--wrap,freeproc -Wl,--wrap,popen \
                              -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,audit_add_rule -Wl,--wrap,audit_restart  \
                              -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,closeproc  -Wl,--wrap,recv -Wl,--wrap,IsDir \
                              -Wl,--wrap,IsLink -Wl,--wrap,IsFile -Wl,--wrap,IsSocket -Wl,--wrap,fprintf -Wl,--wrap,wfopen \
                              -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fgetpos \
                              -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc \
                              -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink -Wl,--wrap,audit_delete_rule \
                              -Wl,--wrap,select -Wl,--wrap,audit_parse -Wl,--wrap,symlink -Wl,--wrap,SendMSG \
                              -Wl,--wrap,audit_get_rule_list -Wl,--wrap,fim_audit_reload_rules \
                              -Wl,--wrap,search_audit_rule -Wl,--wrap,abspath -Wl,--wrap,atomic_int_get \
                              -Wl,--wrap,atomic_int_set -Wl,--wrap,atomic_int_dec -Wl,--wrap,atomic_int_inc \
                              -Wl,--wrap,pthread_rwlock_wrlock -Wl,--wrap,pthread_rwlock_unlock \
                              -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,OS_SHA1_Str -Wl,--wrap,fim_db_init \
                              -Wl,--wrap,OS_SHA1_File -Wl,--wrap,audit_open -Wl,--wrap,audit_close \
                              -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                              -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                              -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                              -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                              ${DEBUG_OP_WRAPPERS}")

    target_link_libraries(test_syscheck_audit SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_syscheck_audit "${SYSCHECK_AUDIT_FLAGS}")
    add_test(NAME test_syscheck_audit COMMAND test_syscheck_audit)

    # test_audit_parse tests
    add_executable(test_audit_parse test_audit_parse.c)
    target_compile_options(test_audit_parse PRIVATE "-Wall")

    set(AUDIT_PARSE_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap=_mwarn -Wl,--wrap=_minfo \
                           -Wl,--wrap,audit_add_rule -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,popen \
                           -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush \
                           -Wl,--wrap,fgets -Wl,--wrap,fgetpos -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite\
                           -Wl,--wrap,remove -Wl,--wrap,fgetc -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink \
                           -Wl,--wrap,audit_delete_rule -Wl,--wrap,realpath -Wl,--wrap,atexit -Wl,--wrap,audit_open\
                           -Wl,--wrap,get_user -Wl,--wrap,get_group -Wl,--wrap,readlink -Wl,--wrap,audit_get_rule_list \
                           -Wl,--wrap,SendMSG -Wl,--wrap,fim_whodata_event -Wl,--wrap,search_audit_rule \
                           -Wl,--wrap,audit_close -Wl,--wrap,fim_manipulated_audit_rules -Wl,--wrap,wfopen \
                           -Wl,--wrap,fim_audit_reload_rules -Wl,--wrap,remove_audit_rule_syscheck \
                           -Wl,--wrap,atomic_int_get -Wl,--wrap,atomic_int_set -Wl,--wrap,atomic_int_dec \
                           -Wl,--wrap,atomic_int_inc -Wl,--wrap,pthread_rwlock_wrlock -Wl,--wrap,pthread_rwlock_unlock \
                           -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                           -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                           -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_init \
                           -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                           -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                           ${DEBUG_OP_WRAPPERS}")

    target_link_libraries(test_audit_parse SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_parse "${AUDIT_PARSE_FLAGS}")
    add_test(NAME test_audit_parse COMMAND test_audit_parse)
else()
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
    add_executable(test_win_whodata test_win_whodata.c)
    target_compile_options(test_win_whodata PRIVATE "-Wall")
    set(WIN_WHODATA_FLAGS "-Wl,--wrap,wstr_replace -Wl,--wrap,SendMSG -Wl,--wrap,popen \
                           -Wl,--wrap,free_whodata_event -Wl,--wrap,IsFile -Wl,--wrap=remove \
                           -Wl,--wrap=fim_db_get_count_registry_data -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                           -Wl,--wrap,wm_exec -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,atexit -Wl,--wrap,wfopen \
                           -Wl,--wrap,check_path_type -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,fim_whodata_event \
                           -Wl,--wrap,fim_checker -Wl,--wrap,os_random -Wl,--wrap,wpopenv -Wl,--wrap,atomic_int_get\
                           -Wl,--wrap,convert_windows_string -Wl,--wrap,FOREVER -Wl,--wrap,wpclose \
                           -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,fprintf \
                           -Wl,--wrap,fgets -Wl,--wrap,wstr_split -Wl,--wrap,pthread_rwlock_wrlock \
                           -Wl,--wrap,fgetpos -Wl,--wrap,fgetc -Wl,--wrap,getDefine_Int -Wl,--wrap,pthread_rwlock_rdlock \
                           -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                           -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                           -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                           -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_init -Wl,--wrap=fim_run_integrity \
                           -Wl,--wrap=fim_db_transaction_start -Wl,--wrap=fim_db_transaction_sync_row \
                           -Wl,--wrap=fim_db_transaction_deleted_rows,--wrap=fim_sync_push_msg \
                           -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                           -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown ${HASH_OP_WRAPPERS} \
                           ${DEBUG_OP_WRAPPERS}")
    target_link_libraries(test_win_whodata SYSCHECK_EVENT_O ${TEST_EVENT_DEPS} fimdb)

    target_link_libraries(test_win_whodata "${WIN_WHODATA_FLAGS}")
    add_test(NAME test_win_whodata COMMAND test_win_whodata)
endif()

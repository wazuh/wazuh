include_directories((${SRC_FOLDER}/syscheckd))

link_directories(${SRC_FOLDER}/unit_tests/wrappers/syscheckd/registry)

# registry.c tests
add_executable(test_registry test_registry.c)

target_compile_options(test_registry PRIVATE "-Wall")

target_link_libraries(test_registry SYSCHECK_O ${TEST_DEPS} fim_shared)
target_link_libraries(test_registry "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn
                                     -Wl,--wrap=send_syscheck_msg,--wrap=os_random -Wl,--wrap,getpid
                                     -Wl,--wrap=fim_registry_value_diff
                                     -Wl,--wrap=get_registry_permissions
                                     -Wl,--wrap=decode_win_acl_json,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock
                                     -Wl,--wrap,fim_db_init,--wrap=fim_sync_push_msg
                                     -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path
                                     -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode
                                     -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start
                                     -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows
                                     -Wl,--wrap=fim_dbsync_registry_key_json_event,--wrap=fim_dbsync_registry_value_json_event
                                     -Wl,--wrap=fim_diff_process_delete_registry,--wrap=fim_diff_process_delete_value")

add_test(NAME test_registry COMMAND test_registry)

# events.c tests
add_executable(test_events test_events.c)

target_compile_options(test_events PRIVATE "-Wall")

target_link_libraries(test_events SYSCHECK_O ${TEST_DEPS} fim_shared)
target_link_libraries(test_events "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn,--wrap=_merror_exit,--wrap=_mterror_exit")

add_test(NAME test_events COMMAND test_events)

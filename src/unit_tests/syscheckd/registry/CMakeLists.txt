include_directories((${SRC_FOLDER}/syscheckd))

# registry.c tests
add_executable(test_registry test_registry.c)

target_compile_options(test_registry PRIVATE "-Wall")

target_link_libraries(test_registry SYSCHECK_O ${TEST_DEPS})
target_link_libraries(test_registry "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn
                                     -Wl,--wrap=send_syscheck_msg,--wrap=os_random -Wl,--wrap,getpid
                                     -Wl,--wrap=fim_db_set_all_registry_data_unscanned
                                     -Wl,--wrap=fim_db_set_all_registry_key_unscanned
                                     -Wl,--wrap=fim_db_get_registry_key,--wrap=fim_db_insert_registry_key
                                     -Wl,--wrap=fim_db_set_registry_key_scanned,--wrap=fim_db_get_registry_key_rowid
                                     -Wl,--wrap=fim_db_get_registry_data,--wrap=fim_db_insert_registry_data
                                     -Wl,--wrap=fim_db_remove_registry_value_data,--wrap=fim_db_get_values_from_registry_key
                                     -Wl,--wrap=fim_db_process_read_registry_data_file,--wrap=fim_db_remove_registry_key
                                     -Wl,--wrap=fim_db_get_registry_keys_not_scanned,--wrap=fim_db_get_registry_data_not_scanned
                                     -Wl,--wrap=fim_db_set_registry_data_scanned,--wrap=fim_registry_value_diff
                                     -Wl,--wrap=fim_db_process_read_file,--wrap=get_registry_permissions
                                     -Wl,--wrap=decode_win_permissions,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock")

add_test(NAME test_registry COMMAND test_registry)

# events.c tests
add_executable(test_events test_events.c)

target_compile_options(test_events PRIVATE "-Wall")

target_link_libraries(test_events SYSCHECK_O ${TEST_DEPS})
target_link_libraries(test_events "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn")

add_test(NAME test_events COMMAND test_events)

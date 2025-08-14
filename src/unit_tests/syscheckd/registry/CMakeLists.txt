include_directories(${SRC_FOLDER}/syscheckd/src)
include_directories(${SRC_FOLDER}/syscheckd/include)

link_directories(${SRC_FOLDER}/unit_tests/wrappers/syscheckd/registry)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# registry.c tests
add_executable(test_registry test_registry.c)

target_compile_options(test_registry PRIVATE "-Wall")
target_compile_options(test_registry PRIVATE "-g")

target_link_libraries(test_registry SYSCHECK_O ${TEST_DEPS} fim_shared)
target_link_libraries(test_registry "${DEBUG_OP_WRAPPERS} \
                                     -Wl,--wrap=send_syscheck_msg  -Wl,--wrap,persist_syscheck_msg -Wl,--wrap=os_random -Wl,--wrap,getpid \
                                     -Wl,--wrap=fim_registry_value_diff -Wl,--wrap=get_registry_permissions \
                                     -Wl,--wrap=decode_win_acl_json -Wl,--wrap=pthread_mutex_lock -Wl,--wrap=pthread_mutex_unlock \
                                     -Wl,--wrap,fim_db_init -Wl,--wrap=fim_sync_push_msg -Wl,--wrap=syscom_dispatch \
                                     -Wl,--wrap=fim_db_get_count_registry_data -Wl,--wrap=fim_db_get_count_registry_key \
                                     -Wl,--wrap=fim_db_file_pattern_search -Wl,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                                     -Wl,--wrap=fim_db_file_update -Wl,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                                     -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_run_integrity -Wl,--wrap=fim_db_transaction_start \
                                     -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows \
                                     -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                     -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff \
                                     -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")

if(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_registry fimdb)
endif(${TARGET} STREQUAL "winagent")

add_test(NAME test_registry COMMAND test_registry)

# events.c tests
add_executable(test_events test_events.c)

target_compile_options(test_events PRIVATE "-Wall")

target_link_libraries(test_events SYSCHECK_O ${TEST_DEPS} fim_shared)
target_link_libraries(test_events "${DEBUG_OP_WRAPPERS} \
                                   -Wl,--wrap=fim_db_transaction_sync_row -Wl,--wrap=fim_db_transaction_deleted_rows -Wl,--wrap=fim_run_integrity \
                                   -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_transaction_start -Wl,--wrap,fim_db_init \
                                   -Wl,--wrap=fim_db_get_count_registry_data -Wl,--wrap=fim_db_get_count_registry_key -Wl,--wrap=syscom_dispatch \
                                   -Wl,--wrap=fim_db_file_update -Wl,--wrap,fim_db_get_path -Wl,--wrap=fim_db_file_pattern_search -Wl,--wrap=fim_db_remove_path \
                                   -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown \
                                   -Wl,--wrap,asp_create -Wl,--wrap,asp_sync_module -Wl,--wrap,asp_parse_response_buffer -Wl,--wrap,asp_persist_diff")

if(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_events fimdb)
endif(${TARGET} STREQUAL "winagent")

add_test(NAME test_events COMMAND test_events)

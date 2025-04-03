
#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND wdb_tests_names "test_wdb_integrity")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_errmsg \
                         -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,EVP_DigestInit_ex -Wl,--wrap,EVP_DigestUpdate -Wl,--wrap,_DigestFinal_ex \
                         -Wl,--wrap,sqlite3_bind_int64 -Wl,--wrap,sqlite3_column_text -Wl,--wrap,_mdebug2 -Wl,--wrap,wdb_exec_stmt \
                         -Wl,--wrap,time -Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,wdb_init_stmt_in_cache -Wl,--wrap,wdb_begin2 ${DEBUG_OP_WRAPPERS} \
                         -Wl,--wrap,router_provider_send")

# Add server specific tests to the list
list(APPEND wdb_tests_names "test_wdb_fim")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_begin2 \
                        -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text \
                        -Wl,--wrap,sqlite3_bind_int64 -Wl,--wrap,sqlite3_step -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_bind_int \
                        ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_parser")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_scan_info_get -Wl,--wrap,wdb_fim_update_date_entry -Wl,--wrap,wdb_fim_clean_old_entries \
                        -Wl,--wrap,wdb_scan_info_update -Wl,--wrap,wdb_scan_info_fim_checks_control -Wl,--wrap,wdb_syscheck_load \
                        -Wl,--wrap,wdb_fim_delete -Wl,--wrap,wdb_syscheck_save -Wl,--wrap,wdb_syscheck_save2 \
                        -Wl,--wrap,wdbi_query_checksum -Wl,--wrap,wdbi_query_clear -Wl,--wrap,wdb_stmt_cache \
                        -Wl,--wrap,sqlite3_changes -Wl,--wrap,sqlite3_bind_int -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_last_insert_rowid \
                        -Wl,--wrap,sqlite3_step -Wl,--wrap,wdb_step -Wl,--wrap,wdb_open_agent2 -Wl,--wrap,wdb_leave \
                        -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,wdb_open_global \
                        -Wl,--wrap,wdb_global_agent_exists -Wl,--wrap,wdb_sca_find \
                        -Wl,--wrap,cJSON_PrintUnformatted \
                        -Wl,--wrap,wdb_agents_get_sys_osinfo -Wl,--wrap,wdb_osinfo_save \
                        -Wl,--wrap,wdb_agents_get_packages -Wl,--wrap,wdb_agents_get_hotfixes -Wl,--wrap,close -Wl,--wrap,getpid \
                        -Wl,--wrap,wdb_package_save -Wl,--wrap,wdb_hotfix_save -Wl,--wrap,wdb_package_update -Wl,--wrap,wdb_package_delete \
                        -Wl,--wrap,wdb_hotfix_delete -Wl,--wrap,time -Wl,--wrap,wdbi_update_attempt  -Wl,--wrap,wdbi_update_completion \
                        -Wl,--wrap,sqlite3_reset -Wl,--wrap,sqlite3_prepare_v2 \
                        -Wl,--wrap,sqlite3_clear_bindings -Wl,--wrap,wdb_get_cache_stmt -Wl,--wrap,sqlite3_column_text \
                        -Wl,--wrap,sqlite3_column_int -Wl,--wrap,sqlite3_column_double -Wl,--wrap,sqlite3_bind_null -Wl,--wrap,sqlite3_bind_int64\
                        -Wl,--wrap,sqlite3_bind_double -Wl,--wrap,wdb_upsert_dbsync -Wl,--wrap,wdb_delete_dbsync \
                        -Wl,--wrap,wdb_get_config -Wl,--wrap,wdb_get_internal_config -Wl,--wrap,wdb_finalize_all_statements \
                        -Wl,--wrap,wdb_global_create_backup -Wl,--wrap,wdb_commit2 -Wl,--wrap,wdb_vacuum -Wl,--wrap,wdb_get_db_state \
                        -Wl,--wrap,wdb_update_last_vacuum_data -Wl,--wrap,wdb_get_db_free_pages_percentage \
                        -Wl,--wrap,w_is_file -Wl,--wrap,wdb_close\
                        -Wl,--wrap,wdb_pool_leave ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_global_parser")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_open_global -Wl,--wrap,wdb_leave -Wl,--wrap,wdb_exec -Wl,--wrap,sqlite3_errmsg \
                             -Wl,--wrap,wdb_global_insert_agent -Wl,--wrap,wdb_global_update_agent_name -Wl,--wrap,wdb_global_update_agent_version \
                             -Wl,--wrap,wdb_global_get_agent_labels -Wl,--wrap,wdb_global_del_agent_labels -Wl,--wrap,wdb_global_set_agent_label \
                             -Wl,--wrap,wdb_global_update_agent_keepalive -Wl,--wrap,wdb_global_update_agent_connection_status -Wl,--wrap,wdb_global_update_agent_status_code \
                             -Wl,--wrap,wdb_global_delete_agent -Wl,--wrap,wdb_global_select_agent_name -Wl,--wrap,wdb_global_select_agent_group \
                             -Wl,--wrap,wdb_global_delete_agent_belong -Wl,--wrap,wdb_global_find_agent -Wl,--wrap,wdb_global_find_group \
                             -Wl,--wrap,wdb_global_insert_agent_group -Wl,--wrap,wdb_global_insert_agent_belong -Wl,--wrap,wdb_global_delete_group_belong \
                             -Wl,--wrap,wdb_global_delete_group -Wl,--wrap,wdb_global_select_groups \
                             -Wl,--wrap,wdb_global_sync_agent_info_get -Wl,--wrap,wdb_global_sync_agent_info_set \
                             -Wl,--wrap,wdb_global_get_all_agents -Wl,--wrap,wdb_global_get_agent_info -Wl,--wrap,wdb_global_reset_agents_connection \
                             -Wl,--wrap,wdb_global_get_agents_by_connection_status -Wl,--wrap,wdb_global_get_agents_to_disconnect \
                             -Wl,--wrap,sqlite3_step -Wl,--wrap,wdb_global_get_groups_integrity -Wl,--wrap,wdb_global_get_backups \
                             -Wl,--wrap,wdb_global_restore_backup -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                             -Wl,--wrap,wdb_global_select_group_belong -Wl,--wrap,wdb_global_set_agent_groups -Wl,--wrap,wdb_global_sync_agent_groups_get \
                             -Wl,--wrap,wdb_global_get_group_agents -Wl,--wrap,w_inc_queries_total -Wl,--wrap,w_inc_global -Wl,--wrap,gettimeofday \
                             -Wl,--wrap,w_inc_global_sql -Wl,--wrap,w_inc_global_sql_time -Wl,--wrap,w_inc_global_vacuum -Wl,--wrap,w_inc_global_vacuum_time \
                             -Wl,--wrap,w_inc_global_get_fragmentation -Wl,--wrap,w_inc_global_get_fragmentation_time \
                             -Wl,--wrap,w_inc_global_agent_insert_agent -Wl,--wrap,w_inc_global_agent_insert_agent_time -Wl,--wrap,w_inc_global_agent_update_agent_name \
                             -Wl,--wrap,w_inc_global_agent_update_agent_name_time -Wl,--wrap,w_inc_global_agent_update_agent_data -Wl,--wrap,w_inc_global_agent_update_agent_data_time \
                             -Wl,--wrap,w_inc_global_labels_get_labels -Wl,--wrap,w_inc_global_labels_get_labels_time -Wl,--wrap,w_inc_global_agent_update_keepalive \
                             -Wl,--wrap,w_inc_global_agent_update_keepalive_time \
                             -Wl,--wrap,w_inc_global_agent_update_connection_status -Wl,--wrap,w_inc_global_agent_update_connection_status_time \
                             -Wl,--wrap,w_inc_global_agent_update_status_code -Wl,--wrap,w_inc_global_agent_update_status_code_time \
                             -Wl,--wrap,w_inc_global_agent_delete_agent -Wl,--wrap,w_inc_global_agent_delete_agent_time -Wl,--wrap,w_inc_global_agent_select_agent_name \
                             -Wl,--wrap,w_inc_global_agent_select_agent_name_time -Wl,--wrap,w_inc_global_agent_select_agent_group \
                             -Wl,--wrap,w_inc_global_agent_select_agent_group_time -Wl,--wrap,w_inc_global_agent_find_agent -Wl,--wrap,w_inc_global_agent_find_agent_time \
                             -Wl,--wrap,w_inc_global_group_find_group -Wl,--wrap,w_inc_global_group_find_group_time -Wl,--wrap,w_inc_global_group_insert_agent_group \
                             -Wl,--wrap,w_inc_global_group_insert_agent_group_time -Wl,--wrap,w_inc_global_belongs_select_group_belong \
                             -Wl,--wrap,w_inc_global_belongs_select_group_belong_time -Wl,--wrap,w_inc_global_belongs_get_group_agent \
                             -Wl,--wrap,w_inc_global_belongs_get_group_agent_time -Wl,--wrap,w_inc_global_group_delete_group -Wl,--wrap,w_inc_global_group_delete_group_time \
                             -Wl,--wrap,w_inc_global_group_select_groups -Wl,--wrap,w_inc_global_group_select_groups_time -Wl,--wrap,w_inc_global_agent_sync_agent_info_get \
                             -Wl,--wrap,w_inc_global_agent_sync_agent_info_get_time -Wl,--wrap,w_inc_global_agent_sync_agent_info_set \
                             -Wl,--wrap,w_inc_global_agent_sync_agent_info_set_time -Wl,--wrap,w_inc_global_agent_set_agent_groups -Wl,--wrap,w_inc_global_agent_set_agent_groups_time \
                             -Wl,--wrap,w_inc_global_agent_sync_agent_groups_get -Wl,--wrap,w_inc_global_agent_sync_agent_groups_get_time \
                             -Wl,--wrap,w_inc_global_agent_get_groups_integrity -Wl,--wrap,w_inc_global_agent_get_groups_integrity_time -Wl,--wrap,w_inc_global_agent_disconnect_agents \
                             -Wl,--wrap,w_inc_global_agent_disconnect_agents_time -Wl,--wrap,w_inc_global_agent_get_all_agents -Wl,--wrap,w_inc_global_agent_get_all_agents_time \
                             -Wl,--wrap,w_inc_global_agent_get_agent_info -Wl,--wrap,w_inc_global_agent_get_agent_info_time -Wl,--wrap,w_inc_global_agent_reset_agents_connection \
                             -Wl,--wrap,w_inc_global_agent_reset_agents_connection_time -Wl,--wrap,w_inc_global_agent_get_agents_by_connection_status \
                             -Wl,--wrap,w_inc_global_agent_get_agents_by_connection_status_time -Wl,--wrap,w_inc_global_backup -Wl,--wrap,w_inc_global_backup_time \
                             -Wl,--wrap,wdb_commit2 -Wl,--wrap,wdb_vacuum -Wl,--wrap,wdb_get_db_state -Wl,--wrap,wdb_finalize_all_statements \
                             -Wl,--wrap,wdb_update_last_vacuum_data -Wl,--wrap,wdb_get_db_free_pages_percentage -Wl,--wrap,wdb_global_get_distinct_agent_groups \
                             -Wl,--wrap,w_inc_global_agent_get_distinct_groups -Wl,--wrap,w_inc_global_agent_get_distinct_groups_time \
                             -Wl,--wrap,w_is_file -Wl,--wrap,wdb_close -Wl,--wrap,w_inc_global_open_time -Wl,--wrap,wdb_pool_leave \
                             -Wl,--wrap,w_inc_global_agent_recalculate_agent_group_hashes \ -Wl,--wrap,w_inc_global_agent_recalculate_agent_group_hashes_time \
                             -Wl,--wrap,wdb_global_recalculate_all_agent_groups_hash -Wl,--wrap,wdb_global_get_all_agents_context ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_global")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_exec -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,wdb_begin2 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_int \
                            -Wl,--wrap,wdb_exec_stmt -Wl,--wrap,wdb_exec_stmt_sized -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,wfopen \
                            -Wl,--wrap,sqlite3_bind_parameter_index -Wl,--wrap,cJSON_Delete -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_column_int \
                            -Wl,--wrap,wdb_init_stmt_in_cache -Wl,--wrap,wdb_get_global_group_hash -Wl,--wrap,wdb_commit2 -Wl,--wrap,wdb_finalize_all_statements \
                            -Wl,--wrap,sqlite3_prepare_v2 -Wl,--wrap,w_get_timestamp -Wl,--wrap,wdb_exec_stmt_silent -Wl,--wrap,w_compress_gzfile \
                            -Wl,--wrap,sqlite3_finalize -Wl,--wrap,popen -Wl,--wrap,unlink -Wl,--wrap,getpid -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,readdir \
                            -Wl,--wrap,stat -Wl,--wrap,w_uncompress_gzfile -Wl,--wrap,wdb_leave -Wl,--wrap,wdb_close -Wl,--wrap,rename -Wl,--wrap,time \
                            -Wl,--wrap,wdb_exec_stmt_single_column -Wl,--wrap,w_is_single_node -Wl,--wrap,sqlite3_column_text ${DEBUG_OP_WRAPPERS} ${STDIO_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_agents")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_init_stmt_in_cache -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,wdb_exec_stmt_silent  -Wl,--wrap,sqlite3_step \
                             -Wl,--wrap,wdb_exec_stmt -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,cJSON_Delete \
                             -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateString -Wl,--wrap,cJSON_AddItemToObject \
                             -Wl,--wrap,cJSON_AddItemToArray -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_GetObjectItem -Wl,--wrap,wdb_exec_stmt_sized \
                             -Wl,--wrap,wdb_exec_stmt_send -Wl,--wrap,wdbi_check_sync_status -Wl,--wrap,sqlite3_bind_double")


list(APPEND wdb_tests_names "test_wdb_global_helpers")
list(APPEND wdb_tests_flags "-Wl,--wrap,strerror \
                             -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateString -Wl,--wrap,cJSON_Parse \
                             -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,cJSON_AddItemToArray -Wl,--wrap,cJSON_AddNumberToObject \
                             -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,cJSON_GetObjectItem \
                             -Wl,--wrap,cJSON_Delete -Wl,--wrap,time -Wl,--wrap,fopen -Wl,--wrap,popen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap=fgetc\
                             -Wl,--wrap,fclose -Wl,--wrap,cJSON_AddArrayToObject -Wl,--wrap,remove -Wl,--wrap,opendir -Wl,--wrap,readdir -Wl,--wrap,closedir \
                             -Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result -Wl,--wrap,wdbc_query_parse_json -Wl,--wrap,wdbc_query_parse \
                             -Wl,--wrap,wdb_create_profile -Wl,--wrap,Privsep_GetUser -Wl,--wrap,Privsep_GetGroup -Wl,--wrap,chown \
                             -Wl,--wrap,chmod -Wl,--wrap,IsDir -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek -Wl,--wrap,get_node_name \
                             -Wl,--wrap,rbtree_insert -Wl,--wrap,wfopen \
                             -Wl,--wrap,stat -Wl,--wrap,fgetpos ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_agents_helpers")
list(APPEND wdb_tests_flags "-Wl,--wrap,strerror \
                             -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateString -Wl,--wrap,cJSON_Parse \
                             -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,cJSON_AddItemToArray -Wl,--wrap,cJSON_AddNumberToObject \
                             -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,cJSON_GetObjectItem \
                             -Wl,--wrap,cJSON_ParseWithOpts -Wl,--wrap,cJSON_Delete -Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result \
                             -Wl,--wrap,cJSON_AddItemToArray -Wl,--wrap,cJSON_Duplicate -Wl,--wrap,wdbc_query_parse_json -Wl,--wrap,wdbc_query_parse \
                             -Wl,--wrap,cJSON_AddBoolToObject -Wl,--wrap,cJSON_CreateNumber ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,strerror -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,time_diff \
                             -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,OSHash_Get -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Delete_ex \
                             -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,sqlite3_open_v2 -Wl,--wrap,sqlite3_close_v2 -Wl,--wrap,sqlite3_step -Wl,--wrap,wdb_step \
                             -Wl,--wrap,sqlite3_column_count -Wl,--wrap,sqlite3_column_type -Wl,--wrap,sqlite3_column_name -Wl,--wrap,sqlite3_column_double \
                             -Wl,--wrap,sqlite3_column_text -Wl,--wrap,sqlite3_prepare_v2 -Wl,--wrap,sqlite3_finalize -Wl,--wrap,sqlite3_reset \
                             -Wl,--wrap,sqlite3_clear_bindings -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,sqlite3_sql -Wl,--wrap,OS_SendSecureTCP  \
                             -Wl,--wrap,gettimeofday -Wl,--wrap,w_inc_global_rollback -Wl,--wrap,w_inc_global_rollback_time \
                             -Wl,--wrap,OS_SetSendTimeout -Wl,--wrap,time -Wl,--wrap,sqlite3_column_int -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,rwlock_lock_write \
                             -Wl,--wrap,rwlock_lock_read -Wl,--wrap,rwlock_unlock -Wl,--wrap,wdb_pool_get -Wl,--wrap,wdb_pool_get_or_create \
                             -Wl,--wrap,wdb_pool_leave -Wl,--wrap,wdb_pool_keys -Wl,--wrap,wdb_pool_clean -Wl,--wrap,getuid -Wl,--wrap,chmod \
                             -Wl,--wrap,stat -Wl,--wrap,sqlite3_exec -Wl,--wrap,sqlite3_free ${HASH_OP_WRAPPERS} ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_upgrade")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_count_tables_with_name \
                             -Wl,--wrap,wdb_sql_exec -Wl,--wrap,wdb_metadata_get_entry -Wl,--wrap,fopen -Wl,--wrap,popen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose \
                             -Wl,--wrap,remove -Wl,--wrap,opendir -Wl,--wrap,readdir -Wl,--wrap,closedir -Wl,--wrap,fflush -Wl,--wrap,fseek -Wl,--wrap,fgets \
                             -Wl,--wrap,wdb_init -Wl,--wrap,wdb_close -Wl,--wrap,wdb_create_global -Wl,--wrap,wdb_pool_append -Wl,--wrap,chmod -Wl,--wrap,stat \
                             -Wl,--wrap,unlink -Wl,--wrap,getpid -Wl,--wrap,time -Wl,--wrap,sqlite3_open_v2 -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,sqlite3_close_v2 \
                             -Wl,--wrap,sqlite3_prepare_v2 -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_column_int -Wl,--wrap,sqlite3_finalize -Wl,--wrap,fgetpos \
                             -Wl,--wrap,fgetc -Wl,--wrap,wdb_global_create_backup -Wl,--wrap,wdb_global_get_most_recent_backup -Wl,--wrap,wdb_global_restore_backup \
                             -Wl,--wrap,wdb_global_adjust_v4 -Wl,--wrap,wfopen ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_metadata")
list(APPEND wdb_tests_flags "-Wl,--wrap,sqlite3_prepare_v2 -Wl,--wrap,sqlite3_errmsg \
                             -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_finalize -Wl,--wrap,sqlite3_column_int \
                             ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_task_parser")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_task_insert_task -Wl,--wrap,wdb_task_get_upgrade_task_status -Wl,--wrap,wdb_task_update_upgrade_task_status -Wl,--wrap,wdb_task_get_upgrade_task_by_agent_id \
                             -Wl,--wrap,wdb_task_cancel_upgrade_tasks -Wl,--wrap,wdb_task_set_timeout_status -Wl,--wrap,wdb_task_delete_old_entries -Wl,--wrap,wdb_open_tasks \
                             ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_rootcheck")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_bind_int \
                             -Wl,--wrap,sqlite3_last_insert_rowid -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_changes -Wl,--wrap,sqlite3_step \
                             ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_syscollector")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_begin2 -Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text \
                             -Wl,--wrap,sqlite3_bind_int -Wl,--wrap,sqlite3_bind_int64 -Wl,--wrap,sqlite3_step -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_errmsg \
                             -Wl,--wrap,sqlite3_column_text -Wl,--wrap,sqlite3_column_int -Wl,--wrap,sqlite3_bind_double \
                             -Wl,--wrap,sqlite3_bind_null -Wl,--wrap,cJSON_GetStringValue -Wl,--wrap,cJSON_GetObjectItem -Wl,--wrap,cJSON_Parse \
                             -Wl,--wrap,cJSON_Delete -Wl,--wrap,cJSON_IsNumber -Wl,--wrap,cJSON_IsString -Wl,--wrap,wdb_agents_get_sys_osinfo \
                             -Wl,--wrap,wdbi_remove_by_pk \
                             ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_task")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_begin2 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_bind_int \
                             -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_column_int -Wl,--wrap,time -Wl,--wrap,sqlite3_errmsg\
                             -Wl,--wrap,sqlite3_column_text -Wl,--wrap,sqlite3_step ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wdb_delta_event")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_get_cache_stmt -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_bind_int -Wl,--wrap,sqlite3_bind_int64 \
                            -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_bind_double -Wl,--wrap,sqlite3_changes \
                            -Wl,--wrap,sqlite3_bind_null -Wl,--wrap,sqlite3_errmsg ${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wazuh_db-config")
list(APPEND wdb_tests_flags "${DEBUG_OP_WRAPPERS}")

list(APPEND wdb_tests_names "test_wazuh_db_state")
list(APPEND wdb_tests_flags "")

list(APPEND wdb_tests_names "test_wdb_com")
list(APPEND wdb_tests_flags "-Wl,--wrap,wdb_create_state_json -Wl,--wrap,wdb_get_config -Wl,--wrap,wdb_get_internal_config")

list(APPEND wdb_tests_names "test_wdb_pool")
list(APPEND wdb_tests_flags "-Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock")

list(APPEND wdb_tests_names "test_create_agent_db")
list(APPEND wdb_tests_flags "-Wl,--wrap,wfopen,--wrap,fopen,--wrap,fclose,--wrap,fflush,--wrap,fgets,--wrap,fgetpos,--wrap,fopen,--wrap,fread,--wrap,fseek,--wrap,fwrite,--wrap,remove,--wrap,fgetc,--wrap,chmod,--wrap,stat,--wrap,OS_MoveFile,--wrap,popen ${DEBUG_OP_WRAPPERS}")

# Add extra compiling flags
add_compile_options(-Wall)
link_directories(${SRC_FOLDER}/build/shared_modules/router)

# Wazuh-DB objects
FILE(GLOB wazuh_db_objects ${SRC_FOLDER}/wazuh_db/*.o)
list(REMOVE_ITEM wazuh_db_objects ${SRC_FOLDER}/wazuh_db/main.o ${SRC_FOLDER}/wazuh_db/wdb_shared.o)

# Compilig tests
list(LENGTH wdb_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wdb_tests_names ${counter} test_name)
    list(GET wdb_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c ${wazuh_db_objects})

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ${TEST_DEPS}
        router
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

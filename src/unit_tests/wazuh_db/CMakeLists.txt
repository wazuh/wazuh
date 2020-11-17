
list(APPEND wdb_tests_names "test_wdb_integrity")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_errmsg \
                         -Wl,--wrap,EVP_DigestInit_ex -Wl,--wrap,EVP_DigestUpdate -Wl,--wrap,_DigestFinal_ex \
                         -Wl,--wrap,sqlite3_column_text -Wl,--wrap,_mdebug2")

# Add server specific tests to the list
list(APPEND wdb_tests_names "test_wdb_fim")
list(APPEND wdb_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_begin2 \
                        -Wl,--wrap,cJSON_GetStringValue -Wl,--wrap,cJSON_IsNumber \
                        -Wl,--wrap,cJSON_IsObject -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text \
                        -Wl,--wrap,sqlite3_bind_int64 -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_bind_int")

list(APPEND wdb_tests_names "test_wdb_parser")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn \
                        -Wl,--wrap,wdb_scan_info_get -Wl,--wrap,wdb_fim_update_date_entry -Wl,--wrap,wdb_fim_clean_old_entries \
                        -Wl,--wrap,wdb_scan_info_update -Wl,--wrap,wdb_scan_info_fim_checks_control -Wl,--wrap,wdb_syscheck_load \
                        -Wl,--wrap,wdb_fim_delete -Wl,--wrap,wdb_syscheck_save -Wl,--wrap,wdb_syscheck_save2 \
                        -Wl,--wrap,wdbi_query_checksum -Wl,--wrap,wdbi_query_clear -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,wdb_step \
                        -Wl,--wrap,sqlite3_changes -Wl,--wrap,sqlite3_bind_int -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_last_insert_rowid")

list(APPEND wdb_tests_names "test_wdb_global_parser")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn \
                             -Wl,--wrap,wdb_open_global -Wl,--wrap,wdb_leave -Wl,--wrap,wdb_exec -Wl,--wrap,sqlite3_errmsg \
                             -Wl,--wrap,wdb_global_insert_agent -Wl,--wrap,wdb_global_update_agent_name -Wl,--wrap,wdb_global_update_agent_version \
                             -Wl,--wrap,wdb_global_get_agent_labels -Wl,--wrap,wdb_global_del_agent_labels -Wl,--wrap,wdb_global_set_agent_label \
                             -Wl,--wrap,wdb_global_update_agent_keepalive -Wl,--wrap,wdb_global_update_agent_connection_status \
                             -Wl,--wrap,wdb_global_delete_agent -Wl,--wrap,wdb_global_select_agent_name -Wl,--wrap,wdb_global_select_agent_group \
                             -Wl,--wrap,wdb_global_delete_agent_belong -Wl,--wrap,wdb_global_find_agent \
                             -Wl,--wrap,wdb_global_update_agent_group -Wl,--wrap,wdb_global_find_group \
                             -Wl,--wrap,wdb_global_insert_agent_group -Wl,--wrap,wdb_global_insert_agent_belong -Wl,--wrap,wdb_global_delete_group_belong \
                             -Wl,--wrap,wdb_global_delete_group -Wl,--wrap,wdb_global_select_groups -Wl,--wrap,wdb_global_select_agent_keepalive \
                             -Wl,--wrap,wdb_global_sync_agent_info_get -Wl,--wrap,wdb_global_sync_agent_info_set \
                             -Wl,--wrap,wdb_global_get_all_agents -Wl,--wrap,wdb_global_get_agent_info -Wl,--wrap,wdb_global_reset_agents_connection \
                             -Wl,--wrap,wdb_global_get_agents_by_connection_status -Wl,--wrap,wdb_global_get_agents_to_disconnect")

list(APPEND wdb_tests_names "test_wdb_global")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn \
                            -Wl,--wrap,wdb_exec -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,wdb_begin2 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_int \
                            -Wl,--wrap,wdb_exec_stmt -Wl,--wrap,wdb_exec_stmt_sized -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_bind_text \
                            -Wl,--wrap,sqlite3_bind_parameter_index -Wl,--wrap,cJSON_Delete -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_column_int")

list(APPEND wdb_tests_names "test_wdb_agent")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,strerror \
                             -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateString -Wl,--wrap,cJSON_Parse \
                             -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,cJSON_AddItemToArray -Wl,--wrap,cJSON_AddNumberToObject \
                             -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,cJSON_GetObjectItem \
                             -Wl,--wrap,cJSON_Delete -Wl,--wrap,time -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite \
                             -Wl,--wrap,fclose -Wl,--wrap,remove -Wl,--wrap,opendir -Wl,--wrap,readdir -Wl,--wrap,closedir \
                             -Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result -Wl,--wrap,wdbc_query_parse_json -Wl,--wrap,wdbc_query_parse \
                             -Wl,--wrap,wdb_create_profile -Wl,--wrap,Privsep_GetUser -Wl,--wrap,Privsep_GetGroup -Wl,--wrap,chown \
                             -Wl,--wrap,chmod -Wl,--wrap,IsDir -Wl,--wrap,isChroot -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek \
                             -Wl,--wrap,stat")

list(APPEND wdb_tests_names "test_wdb")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,pthread_mutex_lock \
                             -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,OSHash_Get -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Delete_ex \
                             -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,sqlite3_open_v2 -Wl,--wrap,sqlite3_close_v2 -Wl,--wrap,sqlite3_step \
                             -Wl,--wrap,sqlite3_column_count -Wl,--wrap,sqlite3_column_type -Wl,--wrap,sqlite3_column_name -Wl,--wrap,sqlite3_column_double \
                             -Wl,--wrap,sqlite3_column_text")

list(APPEND wdb_tests_names "test_wdb_upgrade")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,wdb_metadata_table_check \
                             -Wl,--wrap,wdb_sql_exec -Wl,--wrap,wdb_metadata_get_entry -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose \
                             -Wl,--wrap,remove -Wl,--wrap,opendir -Wl,--wrap,readdir -Wl,--wrap,closedir -Wl,--wrap,fflush -Wl,--wrap,fseek -Wl,--wrap,fgets \
                             -Wl,--wrap,wdb_init -Wl,--wrap,wdb_close -Wl,--wrap,wdb_create_global -Wl,--wrap,wdb_pool_append -Wl,--wrap,chmod -Wl,--wrap,stat \
                             -Wl,--wrap,unlink -Wl,--wrap,getpid -Wl,--wrap,time -Wl,--wrap,sqlite3_open_v2 -Wl,--wrap,sqlite3_errmsg -Wl,--wrap,sqlite3_close_v2 \
                             -Wl,--wrap,wdb_global_check_manager_keepalive")

list(APPEND wdb_tests_names "test_wdb_metadata")
list(APPEND wdb_tests_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,sqlite3_prepare_v2 -Wl,--wrap,sqlite3_errmsg \
                             -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_finalize -Wl,--wrap,sqlite3_column_int")

# Add extra compiling flags
add_compile_options(-Wall)

list(APPEND wdb_tests_names "test_wdb_rootcheck")
list(APPEND wdb_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_bind_text -Wl,--wrap,sqlite3_bind_int \
                             -Wl,--wrap,sqlite3_last_insert_rowid -Wl,--wrap,wdb_step -Wl,--wrap,sqlite3_changes")

# Compilig tests
list(LENGTH wdb_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wdb_tests_names ${counter} test_name)
    list(GET wdb_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
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

# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_SERVER)

# Add server specific tests to the list
list(APPEND tests_names "test_create_db")
list(APPEND tests_flags "-Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug2 -Wl,--wrap,lstat \
                       -Wl,--wrap,fim_send_scan_info -Wl,--wrap,send_syscheck_msg -Wl,--wrap,readdir \
                       -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,realtime_adddir -Wl,--wrap,HasFilesystem \
                       -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_get_paths_from_inode -Wl,--wrap,delete_target_file \
                       -Wl,--wrap,fim_db_insert_data -Wl,--wrap,OS_MD5_SHA1_SHA256_File -Wl,--wrap,seechanges_addfile\
                       -Wl,--wrap,fim_db_delete_not_scanned -Wl,--wrap,fim_db_set_all_unscanned \
                       -Wl,--wrap,fim_db_set_scanned -Wl,--wrap,get_user -Wl,--wrap,get_group \
                       -Wl,--wrap,fim_db_remove_path")

list(APPEND tests_names "test_syscheck_audit")
list(APPEND tests_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,IsSocket -Wl,--wrap,IsFile -Wl,--wrap,IsDir -Wl,--wrap,IsLink -Wl,--wrap,IsFile -Wl,--wrap,audit_restart \
                       -Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,fopen -Wl,--wrap,fwrite -Wl,--wrap,fprintf -Wl,--wrap,fclose -Wl,--wrap,symlink -Wl,--wrap,unlink \
                       -Wl,--wrap,audit_open -Wl,--wrap,audit_get_rule_list -Wl,--wrap,audit_close -Wl,--wrap,mdebug1 -Wl,--wrap,_mwarn -Wl,--wrap,W_Vector_length -Wl,--wrap,search_audit_rule \
                       -Wl,--wrap,audit_add_rule -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,SendMSG -Wl,--wrap,fim_whodata_event \
                       -Wl,--wrap,openproc -Wl,--wrap,readproc -Wl,--wrap,freeproc -Wl,--wrap,closeproc -Wl,--wrap,_mdebug2 -Wl,--wrap,get_user -Wl,--wrap,get_group -Wl,--wrap,realpath")

list(APPEND tests_names "test_seechanges")
list(APPEND tests_flags " ")

list(APPEND tests_names "test_run_realtime")
list(APPEND tests_flags "-Wl,--wrap,inotify_init -Wl,--wrap,inotify_add_watch -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,read \
                      -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Get -Wl,--wrap,rbtree_insert -Wl,--wrap,_merror -Wl,--wrap,W_Vector_insert_unique")

list(APPEND tests_names "test_syscheck_config")
list(APPEND tests_flags "-Wl,--wrap,_merror")

list(APPEND tests_names "test_syscheck")
list(APPEND tests_flags "-Wl,--wrap,_mwarn -Wl,--wrap,fim_db_init")

list(APPEND tests_names "test_fim_sync")
list(APPEND tests_flags "-Wl,--wrap,fim_send_sync_msg -Wl,--wrap,time -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 \
                      -Wl,--wrap,_merror -Wl,--wrap,_mdebug2 -Wl,--wrap,queue_push_ex -Wl,--wrap,fim_db_get_row_path \
                       -Wl,--wrap,fim_db_get_data_checksum -Wl,--wrap,dbsync_check_msg -Wl,--wrap,fim_send_sync_msg \
                       -Wl,--wrap,fim_db_get_count_range -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_entry_json \
                       -Wl,--wrap,fim_db_data_checksum_range -Wl,--wrap,dbsync_state_msg \
                       -Wl,--wrap,fim_db_sync_path_range")

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
                         -Wl,--wrap=sqlite3_column_text,--wrap=printf,--wrap=fim_send_sync_msg,--wrap=dbsync_state_msg \
                         -Wl,--wrap=fim_entry_json")

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

list(APPEND tests_names "test_dbsync")
list(APPEND tests_flags "-Wl,--wrap,_merror -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                         -Wl,--wrap,connect_to_remoted -Wl,--wrap,send_msg_to_agent -Wl,--wrap,wdbc_query_ex \
                         -Wl,--wrap,wdbc_parse_result")

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

# Set tests dependencies
set(TEST_DEPS SYSCHECK_O ANALYSISD_O -lcmocka -fprofile-arcs -ftest-coverage)

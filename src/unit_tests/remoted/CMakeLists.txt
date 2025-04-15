# Generate remoted library
file(GLOB remoted_files
    ${SRC_FOLDER}/remoted/*.o)

add_compile_options("-g")

add_library(REMOTED_O STATIC ${remoted_files})

set_source_files_properties(
    ${remoted_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    REMOTED_O
    PROPERTIES
    LINKER_LANGUAGE C
)

link_directories(${SRC_FOLDER}/build/shared_modules/router)
include_directories(${SRC_FOLDER}/shared_modules/router/include)
target_link_libraries(REMOTED_O ${WAZUHLIB} ${WAZUHEXT} -lpthread -lrouter)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate remoted tests
list(APPEND remoted_names "test_manager")
list(APPEND remoted_flags "-Wl,--wrap,_mdebug2 -Wl,--wrap,_mdebug1 -Wl,--wrap,w_parser_get_agent \
                            -Wl,--wrap,_merror -Wl,--wrap,_merror_exit -Wl,--wrap,popen \
                            -Wl,--wrap,MergeAppendFile -Wl,--wrap,OS_MoveFile -Wl,--wrap,w_parser_get_group \
                            -Wl,--wrap,wurl_request -Wl,--wrap,TestUnmergeFiles -Wl,--wrap,OS_MD5_File \
                            -Wl,--wrap,open_memstream -Wl,--wrap,OS_MD5_Str -Wl,--wrap,fprintf\
                            -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,OSHash_Delete -Wl,--wrap,OSHash_Get \
                            -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Next -Wl,--wrap,OSHash_SetFreeDataPointer \
                            -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,OSHash_Update -Wl,--wrap,OSHash_Get_Elem_ex \
                            -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Add -Wl,--wrap,OSHash_Add_ex \
                            -Wl,--wrap,checkBinaryFile -Wl,--wrap,OSHash_Set -Wl,--wrap,_minfo \
                            -Wl,--wrap,opendir -Wl,--wrap,cldir_ex_ignore -Wl,--wrap,wreaddir -Wl,--wrap=_mwarn \
                            -Wl,--wrap,closedir -Wl,--wrap,OSHash_Clean -Wl,--wrap,rmdir_ex -Wl,--wrap,mkdir -Wl,--wrap,stat\
                            -Wl,--wrap,OS_SHA256_String -Wl,--wrap,readdir -Wl,--wrap,strerror -Wl,--wrap,wfopen \
                            -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,remove \
                            -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                            -Wl,--wrap,w_copy_file -Wl,--wrap,OSHash_Begin -Wl,--wrap,OSHash_Begin_ex -Wl,--wrap,req_save -Wl,--wrap,send_msg \
                            -Wl,--wrap,wdb_update_agent_keepalive -Wl,--wrap,parse_agent_update_msg \
                            -Wl,--wrap,wdb_update_agent_data -Wl,--wrap,linked_queue_push_ex \
                            -Wl,--wrap,wdb_update_agent_connection_status -Wl,--wrap,wdb_update_agent_status_code -Wl,--wrap,SendMSG -Wl,--wrap,StartMQ \
                            -Wl,--wrap,get_ipv4_string -Wl,--wrap,get_ipv6_string \
                            -Wl,--wrap,wdb_get_agent_group -Wl,--wrap,compare_wazuh_versions \
                            -Wl,--wrap,wdb_set_agent_groups_csv -Wl,--wrap,w_is_single_node \
                            -Wl,--wrap,wdb_get_all_agents -Wl,--wrap,wdb_get_agent_info \
                            -Wl,--wrap,rem_inc_send_ack -Wl,--wrap,rem_inc_recv_ctrl_request -Wl,--wrap,rem_inc_recv_ctrl_keepalive \
                            -Wl,--wrap,rem_inc_recv_ctrl_startup -Wl,--wrap,rem_inc_recv_ctrl_shutdown -Wl,--wrap,pthread_mutex_lock \
                            -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,wdb_get_distinct_agent_groups -Wl,--wrap,unlink -Wl,--wrap,getpid \
                            -Wl,--wrap,w_create_sendsync_payload -Wl,--wrap,w_send_clustered_message")

list(APPEND remoted_names "test_secure")
list(APPEND remoted_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,accept -Wl,--wrap,close \
                            -Wl,--wrap,fclose -Wl,--wrap,fcntl -Wl,--wrap,fflush -Wl,--wrap,fgetc \
                            -Wl,--wrap,fgetpos -Wl,--wrap,fgets -Wl,--wrap,fopen -Wl,--wrap,popen -Wl,--wrap,fread \
                            -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,getpid -Wl,--wrap,key_lock_read \
                            -Wl,--wrap,key_lock_write -Wl,--wrap,key_unlock -Wl,--wrap,nb_close \
                            -Wl,--wrap,nb_open -Wl,--wrap,nb_recv -Wl,--wrap,nb_send -Wl,--wrap,OS_AddSocket \
                            -Wl,--wrap,OS_DeleteSocket -Wl,--wrap,OS_IsAllowedDynamicID -Wl,--wrap,OS_IsAllowedIP \
                            -Wl,--wrap,ReadSecMSG -Wl,--wrap,recvfrom -Wl,--wrap,rem_add_recv \
                            -Wl,--wrap,rem_add_send -Wl,--wrap,rem_dec_tcp -Wl,--wrap,wfopen \
                            -Wl,--wrap,rem_getCounter -Wl,--wrap,rem_inc_recv_ctrl \
                            -Wl,--wrap,rem_inc_recv_unknown -Wl,--wrap,rem_inc_tcp \
                            -Wl,--wrap,rem_msgpush -Wl,--wrap,rem_setCounter -Wl,--wrap,remove \
                            -Wl,--wrap,save_controlmsg -Wl,--wrap,sleep -Wl,--wrap,stat -Wl,--wrap,time \
                            -Wl,--wrap,w_mutex_lock -Wl,--wrap,w_mutex_unlock \
                            -Wl,--wrap,wnotify_add -Wl,--wrap,SendMSG -Wl,--wrap,rem_inc_recv_evt \
                            -Wl,--wrap,OS_DupKeyEntry -Wl,--wrap,OS_FreeKey ${DEBUG_OP_WRAPPERS} \
                            -Wl,--wrap,router_provider_send_fb ${HASH_OP_WRAPPERS}")

list(APPEND remoted_names "test_save_ctrlmsg_thread")
list(APPEND remoted_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,accept -Wl,--wrap,close \
                            -Wl,--wrap,fclose -Wl,--wrap,fcntl -Wl,--wrap,fflush -Wl,--wrap,fgetc \
                            -Wl,--wrap,fgetpos -Wl,--wrap,fgets -Wl,--wrap,fopen -Wl,--wrap,popen -Wl,--wrap,fread \
                            -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,getpid -Wl,--wrap,remove \
                            -Wl,--wrap,FOREVER -Wl,--wrap,linked_queue_push_ex  -Wl,--wrap,linked_queue_pop_ex \
                            -Wl,--wrap,save_controlmsg")

list(APPEND remoted_names "test_netbuffer")
list(APPEND remoted_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 -Wl,--wrap,wnet_order -Wl,--wrap,wnotify_modify \
                            -Wl,--wrap,bqueue_push -Wl,--wrap,bqueue_peek -Wl,--wrap,bqueue_drop -Wl,--wrap,bqueue_clear -Wl,--wrap,sleep \
                            -Wl,--wrap,send -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,fcntl -Wl,--wrap,getpid \
                            -Wl,--wrap,bqueue_used -Wl,--wrap,rem_inc_send_discarded -Wl,--wrap,recv -Wl,--wrap,rem_msgpush")

list(APPEND remoted_names "test_sendmsg")
list(APPEND remoted_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,OS_IsAllowedID -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                            -Wl,--wrap,rwlock_lock_read -Wl,--wrap,rwlock_unlock -Wl,--wrap,CreateSecMSG -Wl,--wrap,nb_queue -Wl,--wrap,time \
                            -Wl,--wrap,sendto -Wl,--wrap,fcntl -Wl,--wrap,rem_add_send")

list(APPEND remoted_names "test_remote-config")
list(APPEND remoted_flags "${DEBUG_OP_WRAPPERS}")

list(APPEND remoted_names "test_syslogtcp")
list(APPEND remoted_flags "-W")

list(APPEND remoted_names "test_remote-state")
list(APPEND remoted_flags "-Wl,--wrap,time -Wl,--wrap,rem_get_qsize -Wl,--wrap,rem_get_tsize \
                            -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Add -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Begin -Wl,--wrap,OSHash_Begin_ex \
                            -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,OSHash_Delete -Wl,--wrap,OSHash_Get -Wl,--wrap,OSHash_Clean \
                            -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Next -Wl,--wrap,OSHash_SetFreeDataPointer \
                            -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,OSHash_Update -Wl,--wrap,OSHash_Get_Elem_ex \
                            -Wl,--wrap,wdb_get_agents_ids_of_current_node -Wl,--wrap,_merror")

list(APPEND remoted_names "test_remcom")
list(APPEND remoted_flags "-Wl,--wrap,rem_create_state_json -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept \
                           -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,getRemoteConfig -Wl,--wrap,rem_create_agents_state_json  \
                           -Wl,--wrap,assign_group_to_agent \
                           -Wl,--wrap,wdb_get_agents_ids_of_current_node -Wl,--wrap,json_parse_agents -Wl,--wrap,getpid ${DEBUG_OP_WRAPPERS}")

list(LENGTH remoted_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET remoted_names ${counter} remoted_test_name)
    list(GET remoted_flags ${counter} remoted_test_flags)

    add_executable(${remoted_test_name} ${remoted_test_name}.c)

    target_link_libraries(
        ${remoted_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        REMOTED_O
        ${TEST_DEPS}
    )

    if(NOT remoted_test_flags STREQUAL " ")
        target_link_libraries(
            ${remoted_test_name}
            ${remoted_test_flags}
        )
    endif()
    add_test(NAME ${remoted_test_name} COMMAND ${remoted_test_name})
endforeach()

# Generate vulnerability detector library
file(GLOB upgrade_files
    ${SRC_FOLDER}/wazuh_modules/*.o
    ${SRC_FOLDER}/wazuh_modules/agent_upgrade/*.o
    ${SRC_FOLDER}/wazuh_modules/agent_upgrade/agent/*.o
    ${SRC_FOLDER}/wazuh_modules/agent_upgrade/manager/*.o)
list(REMOVE_ITEM upgrade_files ${SRC_FOLDER}/wazuh_modules/main.o)

add_library(UPGRADE_O STATIC ${upgrade_files})

set_source_files_properties(
    ${upgrade_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    UPGRADE_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(UPGRADE_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate agent upgrade tests
list(APPEND upgrade_names "test_wm_agent_upgrade")
list(APPEND upgrade_flags "-Wl,--wrap,_mtinfo -Wl,--wrap,pthread_exit -Wl,--wrap,wm_agent_upgrade_check_status -Wl,--wrap,wm_agent_upgrade_listen_messages")

if(${TARGET} STREQUAL "server")

    list(APPEND upgrade_names "test_wm_agent_upgrade_manager")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP \
                            -Wl,--wrap,wm_agent_upgrade_parse_message -Wl,--wrap,wm_agent_upgrade_process_upgrade_command -Wl,--wrap,wm_agent_upgrade_process_upgrade_custom_command -Wl,--wrap,wm_agent_upgrade_process_agent_result_command \
                            -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,wm_agent_upgrade_cancel_pending_upgrades -Wl,--wrap,sleep -Wl,--wrap,CreateThread -Wl,--wrap,getpid")

    list(APPEND upgrade_names "test_wm_agent_upgrade_parsing")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mterror_exit -Wl,--wrap,OS_ReadXML -Wl,--wrap,OS_GetOneContentforElement -Wl,--wrap,OS_ClearXML")

    list(APPEND upgrade_names "test_wm_agent_upgrade_validate")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,wurl_http_get -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,OS_SHA1_File -Wl,--wrap,wurl_request -Wl,--wrap,sleep \
                               -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid")

    list(APPEND upgrade_names "test_wm_agent_upgrade_tasks")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,OSHash_Add_ex -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Update_ex -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,OSHash_Begin -Wl,--wrap,OSHash_Next \
                            -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,close -Wl,--wrap,w_create_sendsync_payload -Wl,--wrap,w_send_clustered_message \
                            -Wl,--wrap,w_is_worker -Wl,--wrap,cJSON_Duplicate -Wl,--wrap,getpid -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Get")

    list(APPEND upgrade_names "test_wm_agent_upgrade_tasks_callbacks")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,wm_agent_upgrade_validate_task_ids_message -Wl,--wrap,wm_agent_upgrade_insert_task_id -Wl,--wrap,wm_agent_upgrade_remove_entry \
                            -Wl,--wrap,wm_agent_upgrade_parse_data_response -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_send_command_to_agent \
                            -Wl,--wrap,wm_agent_upgrade_parse_agent_response -Wl,--wrap,wm_agent_upgrade_send_tasks_information")

    list(APPEND upgrade_names "test_wm_agent_upgrade_commands")
    list(APPEND upgrade_flags "-Wl,--wrap,_mtinfo -Wl,--wrap,_mtwarn \
                            -Wl,--wrap,wm_agent_upgrade_parse_task_module_request -Wl,--wrap,wm_agent_upgrade_task_module_callback -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_validate_id \
                            -Wl,--wrap,wm_agent_upgrade_validate_status -Wl,--wrap,wm_agent_upgrade_validate_version -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,wm_agent_upgrade_create_task_entry -Wl,--wrap,wm_agent_upgrade_parse_data_response \
                            -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,wm_agent_upgrade_prepare_upgrades")

    list(APPEND upgrade_names "test_wm_agent_upgrade_upgrades")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,_mtdebug2 -Wl,--wrap,isChroot -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,close \
                            -Wl,--wrap,wm_agent_upgrade_parse_task_module_request -Wl,--wrap,wm_agent_upgrade_task_module_callback -Wl,--wrap,wm_agent_upgrade_parse_agent_response -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fclose \
                            -Wl,--wrap,OS_SHA1_File -Wl,--wrap,wm_agent_upgrade_get_first_node -Wl,--wrap,wm_agent_upgrade_get_next_node -Wl,--wrap,wm_agent_upgrade_compare_versions -Wl,--wrap,wm_agent_upgrade_remove_entry \
                            -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_validate_wpk -Wl,--wrap,wm_agent_upgrade_validate_wpk_custom \
                            -Wl,--wrap,linked_queue_push_ex -Wl,--wrap,linked_queue_pop_ex -Wl,--wrap,pthread_cond_signal -Wl,--wrap,pthread_cond_wait -Wl,--wrap,CreateThread \
                            -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid")

else()

    list(APPEND upgrade_names "test_wm_agent_upgrade_agent")
    list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mterror_exit -Wl,--wrap,_mtdebug1 -Wl,--wrap,wm_sendmsg -Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose -Wl,--wrap,StartMQ -Wl,--wrap,sleep -Wl,--wrap,close \
                               -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid")

endif()

# Compiling tests
list(LENGTH upgrade_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET upgrade_names ${counter} test_name)
    list(GET upgrade_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        UPGRADE_O
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

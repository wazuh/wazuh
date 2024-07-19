# Generate agent upgrade library
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

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate agent upgrade tests
list(APPEND upgrade_names "test_wm_agent_upgrade")
list(APPEND upgrade_flags "-Wl,--wrap,_mtinfo -Wl,--wrap,wm_agent_upgrade_start_agent_module -Wl,--wrap,wm_agent_upgrade_start_manager_module -Wl,--wrap,getpid -Wl,--wrap,unlink")

if(${TARGET} STREQUAL "server")

    list(APPEND upgrade_names "test_wm_agent_upgrade_manager")
    list(APPEND upgrade_flags "-Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP \
                            -Wl,--wrap,wm_agent_upgrade_parse_message -Wl,--wrap,wm_agent_upgrade_process_upgrade_command -Wl,--wrap,wm_agent_upgrade_process_upgrade_custom_command -Wl,--wrap,wm_agent_upgrade_process_agent_result_command \
                            -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,wm_agent_upgrade_cancel_pending_upgrades -Wl,--wrap,wm_agent_upgrade_process_upgrade_result_command -Wl,--wrap,sleep -Wl,--wrap,CreateThread -Wl,--wrap,pthread_exit -Wl,--wrap,getpid \
                            ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_parsing")
    list(APPEND upgrade_flags "-Wl,--wrap,OS_ReadXML -Wl,--wrap,OS_GetOneContentforElement -Wl,--wrap,OS_ClearXML ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_validate")
    list(APPEND upgrade_flags "-Wl,--wrap,wurl_http_get -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,OS_SHA1_File -Wl,--wrap,wurl_request -Wl,--wrap,sleep -Wl,--wrap,wfopen \
                               -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                               -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_tasks")
    list(APPEND upgrade_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,close -Wl,--wrap,w_create_sendsync_payload -Wl,--wrap,w_send_clustered_message \
                            -Wl,--wrap,w_is_worker -Wl,--wrap,cJSON_Duplicate -Wl,--wrap,getpid ${HASH_OP_WRAPPERS} ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_tasks_callbacks")
    list(APPEND upgrade_flags "-Wl,--wrap,wm_agent_upgrade_validate_task_ids_message -Wl,--wrap,wm_agent_upgrade_remove_entry \
                            -Wl,--wrap,wm_agent_upgrade_parse_data_response -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_send_command_to_agent \
                            -Wl,--wrap,wm_agent_upgrade_parse_agent_response -Wl,--wrap,wm_agent_upgrade_send_tasks_information -Wl,--wrap,wm_agent_upgrade_parse_agent_upgrade_command_response ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_commands")
    list(APPEND upgrade_flags "-Wl,--wrap,wm_agent_upgrade_parse_task_module_request -Wl,--wrap,wm_agent_upgrade_task_module_callback -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_validate_id \
                            -Wl,--wrap,wm_agent_upgrade_validate_status -Wl,--wrap,wm_agent_upgrade_validate_system -Wl,--wrap,wm_agent_upgrade_validate_version -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,wm_agent_upgrade_create_task_entry \
                            -Wl,--wrap,wm_agent_upgrade_parse_data_response -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,wm_agent_upgrade_prepare_upgrades -Wl,--wrap,wm_agent_upgrade_get_agent_ids ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_upgrades")
    list(APPEND upgrade_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,close -Wl,--wrap,popen \
                            -Wl,--wrap,wm_agent_upgrade_parse_task_module_request -Wl,--wrap,wm_agent_upgrade_task_module_callback -Wl,--wrap,wm_agent_upgrade_parse_agent_response -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fclose \
                            -Wl,--wrap,OS_SHA1_File -Wl,--wrap,wm_agent_upgrade_get_first_node -Wl,--wrap,wm_agent_upgrade_get_next_node -Wl,--wrap,compare_wazuh_versions -Wl,--wrap,wm_agent_upgrade_remove_entry \
                            -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_validate_wpk -Wl,--wrap,wm_agent_upgrade_validate_wpk_custom -Wl,--wrap,wm_agent_upgrade_validate_wpk_version \
                            -Wl,--wrap,linked_queue_push_ex -Wl,--wrap,linked_queue_pop_ex -Wl,--wrap,pthread_cond_signal -Wl,--wrap,pthread_cond_wait -Wl,--wrap,CreateThread -Wl,--wrap,wfopen \
                            -Wl,--wrap,wm_agent_upgrade_parse_agent_upgrade_command_response -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                            ${DEBUG_OP_WRAPPERS}")

else()

    list(APPEND upgrade_names "test_wm_agent_upgrade_agent")
    list(APPEND upgrade_flags "-Wl,--wrap,wm_sendmsg -Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose -Wl,--wrap,StartMQ -Wl,--wrap,sleep -Wl,--wrap,close -Wl,--wrap,wfopen \
                               -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,wm_agent_upgrade_process_command \
                               -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid -Wl,--wrap,CreateThread -Wl,--wrap,unlink -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                               -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

    list(APPEND upgrade_names "test_wm_agent_upgrade_com")
    list(APPEND upgrade_flags "-Wl,--wrap,w_ref_parent_folder -Wl,--wrap,w_wpk_unsign -Wl,--wrap,unlink -Wl,--wrap,getpid -Wl,--wrap,gzopen \
                               -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove \
                               -Wl,--wrap,gzclose -Wl,--wrap,gzread -Wl,--wrap,mkstemp -Wl,--wrap,atexit -Wl,--wrap,chmod -Wl,--wrap,stat -Wl,--wrap,wfopen \
                               -Wl,--wrap,OS_SHA1_File -Wl,--wrap,getDefine_Int -Wl,--wrap,cldir_ex -Wl,--wrap,UnmergeFiles -Wl,--wrap,wm_exec -Wl,--wrap,remove \
                               -Wl,--wrap,fgetpos -Wl,--wrap=fgetc  -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

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

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
list(APPEND upgrade_names "test_wm_agent_upgrade_agent")
list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,wm_sendmsg -Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose -Wl,--wrap,StartMQ -Wl,--wrap,sleep -Wl,--wrap,close")

list(APPEND upgrade_names "test_wm_agent_upgrade_manager")
list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP \
                           -Wl,--wrap,wm_agent_upgrade_parse_message -Wl,--wrap,wm_agent_upgrade_process_upgrade_command -Wl,--wrap,wm_agent_upgrade_process_upgrade_custom_command -Wl,--wrap,wm_agent_upgrade_process_agent_result_command")

list(APPEND upgrade_names "test_wm_agent_upgrade_parsing")
list(APPEND upgrade_flags "-Wl,--wrap,_mterror")

list(APPEND upgrade_names "test_wm_agent_upgrade_validate")
list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,wurl_http_get -Wl,--wrap,wdb_agent_version -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,OS_SHA1_File -Wl,--wrap,wurl_request -Wl,--wrap,sleep")

list(APPEND upgrade_names "test_wm_agent_upgrade_tasks_callbacks")
list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtdebug1 -Wl,--wrap,wm_agent_upgrade_validate_task_ids_message -Wl,--wrap,wm_agent_upgrade_insert_task_id -Wl,--wrap,wm_agent_upgrade_remove_entry \
                           -Wl,--wrap,wm_agent_upgrade_parse_response_message -Wl,--wrap,wm_agent_upgrade_validate_task_status_message -Wl,--wrap,wm_agent_upgrade_send_command_to_agent \
                           -Wl,--wrap,wm_agent_upgrade_parse_agent_response -Wl,--wrap,wm_agent_upgrade_send_tasks_information")

list(APPEND upgrade_names "test_wm_agent_upgrade_commands")
list(APPEND upgrade_flags "-Wl,--wrap,_mterror -Wl,--wrap,_mtwarn -Wl,--wrap,_mtdebug1 -Wl,--wrap,_mtdebug2 -Wl,--wrap,isChroot -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,close \
                           -Wl,--wrap,wm_agent_upgrade_parse_task_module_request -Wl,--wrap,wm_agent_upgrade_task_module_callback")

# Compilig tests
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

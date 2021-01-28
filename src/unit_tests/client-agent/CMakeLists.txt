# Generate client-agent library
file(GLOB client-agent_files
    ${SRC_FOLDER}/client-agent/*.o
    ${SRC_FOLDER}/monitord/*.o)

list(REMOVE_ITEM client-agent_files ${SRC_FOLDER}/client-agent/main.o)

add_library(CLIENT-AGENT STATIC ${client-agent_files})

set_source_files_properties(
    ${client-agent_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    CLIENT-AGENT
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(CLIENT-AGENT ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate agentd tests
list(APPEND client-agent_names "test_start_agent")
set(START_AGENT_BASE_FLAGS "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_minfo -Wl,--wrap,_mdebug1 \
                            -Wl,--wrap,w_rotate_log -Wl,--wrap,getDefine_Int -Wl,--wrap,OS_ConnectUDP \
                            -Wl,--wrap,OS_ConnectTCP -Wl,--wrap,OS_SetRecvTimeout -Wl,--wrap,resolveHostname \
                            -Wl,--wrap,send_msg -Wl,--wrap,recv -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,fseek \
                            -Wl,--wrap,fprintf -Wl,--wrap,fflush -Wl,--wrap,ReadSecMSG -Wl,--wrap,wnet_select \
                            -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_SendUDPbySize -Wl,--wrap,getpid")
if(${TARGET} STREQUAL "winagent")
    list(APPEND client-agent_flags "${START_AGENT_BASE_FLAGS} -Wl,--wrap,os_random")
else()
    list(APPEND client-agent_flags "${START_AGENT_BASE_FLAGS} -Wl,--wrap=close")
endif()

list(APPEND client-agent_names "test_notify")
list(APPEND client-agent_flags "-Wl,--wrap,control_check_connection,--wrap,OS_SendUnix,--wrap,OS_RecvUnix,--wrap,close \
                                -Wl,--wrap,sleep,--wrap,w_rotate_log,--wrap,getpid,--wrap,time,--wrap,_mdebug1 \
                                -Wl,--wrap,_mdebug2")

list(APPEND client-agent_names "test_agentd_state")
if(${TARGET} STREQUAL "winagent")
    # cJSON_func@x instead of cJSON_func since linker will be looking for cdecl forma
    # More info at: (https://devblogs.microsoft.com/oldnewthing/20040108-00/?p=41163)
    list(APPEND client-agent_flags "-Wl,--wrap,_merror -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                                -Wl,--wrap,cJSON_CreateObject@0 -Wl,--wrap,cJSON_AddNumberToObject@16 \
                                -Wl,--wrap,cJSON_AddItemToObject@12 -Wl,--wrap,cJSON_AddStringToObject@12 \
                                -Wl,--wrap,cJSON_Delete@4 -Wl,--wrap,strftime \
                                -Wl,--wrap,cJSON_PrintUnformatted@4 -Wl,--wrap,w_agentd_get_buffer_lenght \
                                -Wl,--wrap,cJSON_AddBoolToObject@12")
else()
    list(APPEND client-agent_flags "-Wl,--wrap,_merror -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                                -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_AddNumberToObject -Wl,--wrap,strftime \
                                -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_Delete \
                                -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,w_agentd_get_buffer_lenght \
                                -Wl,--wrap,cJSON_AddBoolToObject")
endif()

list(APPEND client-agent_names "test_buffer")
list(APPEND client-agent_flags "-Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock")

list(LENGTH client-agent_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET client-agent_names ${counter} client-agent_test_name)
    list(GET client-agent_flags ${counter} client-agent_test_flags)

    add_executable(${client-agent_test_name} ${client-agent_test_name}.c)

    target_link_libraries(
        ${client-agent_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        CLIENT-AGENT
        ${TEST_DEPS}
    )

    if(NOT client-agent_test_flags STREQUAL " ")
        target_link_libraries(
            ${client-agent_test_name}
            ${client-agent_test_flags}
        )
    endif()
    add_test(NAME ${client-agent_test_name} COMMAND ${client-agent_test_name})
endforeach()

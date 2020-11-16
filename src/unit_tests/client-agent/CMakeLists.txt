# Generate client-agent library
file(GLOB client-agent_files
    ${SRC_FOLDER}/client-agent/*.o)

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

# Generate Analysisd tests
list(APPEND client-agent_names "test_start_agent")
set(START_AGENT_BASE_FLAGS "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_minfo -Wl,--wrap,_mdebug1 \
                            -Wl,--wrap,w_rotate_log -Wl,--wrap,getDefine_Int -Wl,--wrap,OS_ConnectUDP \
                            -Wl,--wrap,OS_ConnectTCP -Wl,--wrap,OS_SetRecvTimeout -Wl,--wrap,resolveHostname \
                            -Wl,--wrap,send_msg -Wl,--wrap,recv -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,fseek \
                            -Wl,--wrap,fprintf -Wl,--wrap,fflush -Wl,--wrap,ReadSecMSG -Wl,--wrap,wnet_select \
                            -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_SendUDPbySize")
if(${TARGET} STREQUAL "winagent")
    list(APPEND client-agent_flags "${START_AGENT_BASE_FLAGS} -Wl,--wrap,os_random")
else()
    list(APPEND client-agent_flags "${START_AGENT_BASE_FLAGS} -Wl,--wrap=close")
endif()

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

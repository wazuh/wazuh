# Generate os_auth library
file(GLOB os_auth_files
    ${SRC_FOLDER}/os_auth/*.o
    ${SRC_FOLDER}/addagent/*.o)
list(REMOVE_ITEM os_auth_files ${SRC_FOLDER}/os_auth/main-server.o)
list(REMOVE_ITEM os_auth_files ${SRC_FOLDER}/addagent/main.o)

add_library(OS_AUTH_O STATIC ${os_auth_files})

set_source_files_properties(
    ${os_auth_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_AUTH_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_AUTH_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate Analysisd tests
list(APPEND os_auth_names "test_auth_parse")
list(APPEND os_auth_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_minfo -Wl,--wrap,_mdebug1")
list(APPEND os_auth_names "test_auth_validate")
list(APPEND os_auth_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_minfo -Wl,--wrap,_mdebug1 \
                           -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,OS_RemoveAgentGroup -Wl,--wrap,add_remove")
list(APPEND os_auth_names "test_auth_add")
list(APPEND os_auth_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_minfo -Wl,--wrap,_mdebug1")
list(APPEND os_auth_names "test_ssl")
list(APPEND os_auth_flags "-Wl,--wrap,SSL_read -Wl,--wrap=SSL_new")

list(LENGTH os_auth_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_auth_names ${counter} os_auth_test_name)
    list(GET os_auth_flags ${counter} os_auth_test_flags)

    add_executable(${os_auth_test_name} ${os_auth_test_name}.c)

    target_link_libraries(
        ${os_auth_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_AUTH_O
        ${TEST_DEPS}
    )

    if(NOT os_auth_test_flags STREQUAL " ")
        target_link_libraries(
            ${os_auth_test_name}
            ${os_auth_test_flags}
        )
    endif()
    add_test(NAME ${os_auth_test_name} COMMAND ${os_auth_test_name})
endforeach()

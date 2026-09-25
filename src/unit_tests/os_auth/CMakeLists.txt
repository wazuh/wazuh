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

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)
include_directories(${SRC_FOLDER}/os_auth)
# Generate Analysisd tests
list(APPEND os_auth_names "test_auth_parse")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,OS_IsValidIP")
list(APPEND os_auth_names "test_auth_validate")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} \
                           -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,OS_RemoveAgentGroup -Wl,--wrap,add_remove \
                           -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,difftime -Wl,--wrap,OS_IsValidIP")
list(APPEND os_auth_names "test_auth_add")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,OS_IsValidIP")
list(APPEND os_auth_names "test_ssl")
list(APPEND os_auth_flags "-Wl,--wrap,SSL_read -Wl,--wrap=SSL_new")
list(APPEND os_auth_names "test_auth_key_request")
list(APPEND os_auth_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_minfo -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                           -Wl,--wrap,wm_exec -Wl,--wrap,wpopenv -Wl,--wrap,fgets -Wl,--wrap,popen \
                           -Wl,--wrap,cJSON_GetObjectItem -Wl,--wrap,close -Wl,-wrap,send -Wl,--wrap,cJSON_ParseWithOpts \
                           -Wl,--wrap,recv -Wl,--wrap,setsockopt -Wl,--wrap,fcntl -Wl,--wrap,connect -Wl,--wrap,socket \
                           -Wl,--wrap,w_request_agent_add_clustered -Wl,--wrap,sleep -Wl,--wrap,cJSON_Delete -Wl,--wrap,local_add \
                           -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgetpos -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fseek \
                           -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap=fgetc -Wl,--wrap,getpid -Wl,--wrap,wfopen \
                           -Wl,--wrap,external_socket_connect ${HASH_OP_WRAPPERS}")
list(APPEND os_auth_names "test_auth")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} \
                           -Wl,--wrap,os_random -Wl,--wrap,GetRandomNoise -Wl,--wrap,getuname -Wl,--wrap,time -Wl,--wrap,wfopen")
list(APPEND os_auth_names "test_generate_cert")
list (APPEND os_auth_flags "-Wl,--wrap,PEM_write_PrivateKey -Wl,--wrap,PEM_write_X509 -Wl,--wrap,RSA_generate_key_ex \
                            -Wl,--wrap,X509_sign -Wl,--wrap,_merror -Wl,--wrap,wfopen \
                            -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgetpos -Wl,--wrap,fread \
                            -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc -Wl,--wrap,fgets \
                            -Wl,--wrap,RSA_new -Wl,--wrap,EVP_PKEY_new -Wl,--wrap,X509_new -Wl,--wrap,popen")
list(APPEND os_auth_names "test_authd-config")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS}")

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

# main-server.o is excluded from OS_AUTH_O above (it carries authd's main()), so it cannot be
# tested through the shared library like the rest of os_auth. Compile it directly for this one
# target instead, renaming its main() at compile time so it does not collide with cmocka's own.
set_source_files_properties(
    ${SRC_FOLDER}/os_auth/main-server.c
    PROPERTIES
    COMPILE_DEFINITIONS "main=wazuh_authd_main_unused"
)

add_executable(test_main-server test_main-server.c ${SRC_FOLDER}/os_auth/main-server.c)

target_include_directories(test_main-server PRIVATE ${SRC_FOLDER})

target_link_libraries(
    test_main-server
    ${WAZUHLIB}
    ${WAZUHEXT}
    OS_AUTH_O
    ${TEST_DEPS}
    -lpthread
)

target_link_libraries(
    test_main-server
    "${DEBUG_OP_WRAPPERS} -Wl,--wrap,w_get_monotonic_time"
)

add_test(NAME test_main-server COMMAND test_main-server)

link_directories(${SRC_FOLDER}/build/lib)
include_directories(${SRC_FOLDER}/os_auth/include)
include_directories(${SRC_FOLDER}/os_auth/src)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)
# Generate Analysisd tests
list(APPEND os_auth_names "test_auth_parse")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,OS_IsValidIP")
list(APPEND os_auth_names "test_auth_validate")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} \
                           -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,OS_RemoveAgentGroup -Wl,--wrap,add_remove \
                           -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,difftime -Wl,--wrap,OS_IsValidIP")
list(APPEND os_auth_names "test_auth_add")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,OS_IsValidIP")
list(APPEND os_auth_names "test_auth")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} ${STDIO_OP_WRAPPERS} \
                           -Wl,--wrap,os_random -Wl,--wrap,GetRandomNoise -Wl,--wrap,getuname -Wl,--wrap,time -Wl,--wrap,wfopen \
                           -Wl,--wrap,fprintf -Wl,--wrap,popen -Wl,--wrap,pclose")
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
        authd_lib
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

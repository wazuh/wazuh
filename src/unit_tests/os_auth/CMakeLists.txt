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
                           -Wl,--wrap,RAND_bytes -Wl,--wrap,wfopen -Wl,--wrap,fprintf \
                           -Wl,--wrap,popen -Wl,--wrap,pclose")
list(APPEND os_auth_names "test_purge_journal")
# The one wazuh-db call auth.c makes. Wrapped rather than reached: what these tests are about is how
# its ANSWERS are interpreted, and a real socket would make "outstanding" and "the query failed" the
# same case.
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,manager_task_agent_status")
list(APPEND os_auth_names "test_identity_journal")
# Real files in a temporary tree, nothing wrapped but the logs: the journal's file is what an agent's
# credential survives on, so its mode, its append-only writes and what a torn line does are the test.
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS}")
list(APPEND os_auth_names "test_authd-config")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS}")
# authd_read_config()/getAuthdConfig() over the YAML document (w_mconf_* wrapped, Read_Authd_JSON real)
list(APPEND os_auth_names "test_authd-getconfig")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,getDefine_Int_default -Wl,--wrap,w_mconf_load -Wl,--wrap,w_mconf_section")
list(APPEND os_auth_names "test_local-server")
# The mint reads the `remote` section through w_mconf_section (wrapped: the test hands it the JSON that points
# at its own certificate files); the store and the X509 checks run for real on temporary files.
# Re-enrollment (#38993): the row's secret comes from wazuh-db (wrapped: the test hands it the row) and the
# bearer's verdict from the C++ bridge (wrapped here: test_reenroll_verify exercises the real one).
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,w_request_agent_add_clustered -Wl,--wrap,w_mconf_section -Wl,--wrap,OS_IsValidIP \
                           -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,w_reenroll_verify")
list(APPEND os_auth_names "test_enrollment_token_store")
# Real files in a temporary directory: the store's file IS its contract (mode, atomicity, and what
# it never contains), so nothing about the I/O is stubbed away here.
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS}")
# The token CLI is a client of auth.sock: the three socket calls are wrapped so the JSON it sends and the
# answer it reads are both under test; --show-token runs the real codec.
list(APPEND os_auth_names "test_token_cli")
list(APPEND os_auth_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP")
# The re-enrollment bridge (authd's C door into the C++ verifier of shared_modules/utils/jwt/) driven from C with
# the frozen vector: real verifier, real HKDF, nothing wrapped -- the point is that authd's verdict is the one
# remoted and the agent compute for the same bytes.
list(APPEND os_auth_names "test_reenroll_verify")
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

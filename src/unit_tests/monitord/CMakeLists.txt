link_directories(${SRC_FOLDER}/build/lib)
include_directories(${SRC_FOLDER}/monitord/include)
include_directories(${SRC_FOLDER}/monitord/src)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND monitord_tests_names "test_monitord")
list(APPEND monitord_tests_flags "-Wl,--wrap,time\
                                  -Wl,--wrap,StartMQ -Wl,--wrap,SendMSG -Wl,--wrap,getDefine_Int -Wl,--wrap,ReadConfig\
                                  ${DEBUG_OP_WRAPPERS}")

list(APPEND monitord_tests_names "test_monitor_actions")
list(APPEND monitord_tests_flags "-Wl,--wrap,SendMSG -Wl,--wrap,wdb_find_agent\
                                  -Wl,--wrap,wdb_disconnect_agents -Wl,--wrap,time -Wl,--wrap,wdb_get_agent_info -Wl,--wrap,auth_connect\
                                  -Wl,--wrap,get_agent_id_from_name -Wl,--wrap,auth_remove_agent -Wl,--wrap,wdb_get_agents_by_connection_status\
                                  -Wl,--wrap,w_rotate_log -Wl,--wrap,stat -Wl,--wrap,w_query_agentd ${HASH_OP_WRAPPERS} ${DEBUG_OP_WRAPPERS}")

# Add extra compiling flags
add_compile_options(-Wall)

# Compilig tests
list(LENGTH monitord_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET monitord_tests_names ${counter} test_name)
    list(GET monitord_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        monitord_lib
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

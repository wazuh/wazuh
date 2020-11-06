# Generate monitord library
file(GLOB monitord_files
    ${SRC_FOLDER}/monitord/*.o)

# Generate os_maild library
file(GLOB os_maild_files
    ${SRC_FOLDER}/os_maild/*.o)

add_library(MONITOR_O STATIC ${monitord_files})
add_library(MAILD_O STATIC ${os_maild_files})

set_source_files_properties(
    ${monitord_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_source_files_properties(
    ${os_maild_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    MONITOR_O
    PROPERTIES
    LINKER_LANGUAGE C
)

set_target_properties(
    MAILD_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(MONITOR_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)
target_link_libraries(MAILD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

list(APPEND monitord_tests_names "test_monitord")
list(APPEND monitord_tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 -Wl,--wrap,_merror -Wl,--wrap,time\
                                  -Wl,--wrap,StartMQ -Wl,--wrap,SendMSG -Wl,--wrap,getDefine_Int -Wl,--wrap,ReadConfig\
                                  -Wl,--wrap,_merror_exit")

list(APPEND monitord_tests_names "test_monitor_actions")
list(APPEND monitord_tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 -Wl,--wrap,_merror -Wl,--wrap,SendMSG -Wl,--wrap,wdb_find_agent\
                                  -Wl,--wrap,wdb_disconnect_agents -Wl,--wrap,time -Wl,--wrap,OSHash_Add -Wl,--wrap,OSHash_Add_ex\
                                  -Wl,--wrap,OSHash_Create -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,OSHash_Get -Wl,--wrap,wdb_get_agent_info\
                                  -Wl,--wrap,OSHash_Next -Wl,--wrap,OSHash_Begin -Wl,--wrap,OSHash_Delete -Wl,--wrap,auth_connect\
                                  -Wl,--wrap,get_agent_id_from_name -Wl,--wrap,auth_remove_agent -Wl,--wrap,wdb_get_agents_by_connection_status\
                                  -Wl,--wrap,w_rotate_log -Wl,--wrap,stat")

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
        MONITOR_O
        MAILD_O
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

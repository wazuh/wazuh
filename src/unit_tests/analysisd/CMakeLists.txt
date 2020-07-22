# Generate analysisd library
file(GLOB analysisd_files
    ${SRC_FOLDER}/analysisd/*.o
    ${SRC_FOLDER}/analysisd/cdb/*.o
    ${SRC_FOLDER}/analysisd/decoders/*.o
    ${SRC_FOLDER}/analysisd/decoders/plugins/*.o
    ${SRC_FOLDER}/analysisd/compiled_rules/*.o)

add_library(ANALYSISD_O STATIC ${analysisd_files})

set_source_files_properties(
    ${analysisd_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    ANALYSISD_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(ANALYSISD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate Analysisd tests
list(APPEND analysisd_names "test_analysisd_syscheck")
list(APPEND analysisd_flags "-Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result -Wl,--wrap,_merror -Wl,--wrap,_mdebug1")

list(APPEND analysisd_names "test_dbsync")
list(APPEND analysisd_flags "-Wl,--wrap,_merror -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                         -Wl,--wrap,connect_to_remoted -Wl,--wrap,send_msg_to_agent -Wl,--wrap,wdbc_query_ex \
                         -Wl,--wrap,wdbc_parse_result")

list(APPEND analysisd_names "test_mitre")
list(APPEND analysisd_flags "-Wl,--wrap,wdbc_query_ex -Wl,--wrap,_merror -Wl,--wrap,wdbc_query_parse_json")

LIST(APPEND analysisd_names "test_same_different_loop")
LIST(APPEND analysisd_flags "-W")

LIST(APPEND analysisd_names "test_logtest")
LIST(APPEND analysisd_flags "-Wl,--wrap,ReadConfig -Wl,--wrap,_merror -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,OSHash_Create \
                             -Wl,--wrap,pthread_mutex_init -Wl,--wrap,_minfo -Wl,--wrap,_w_mutex_init -Wl,--wrap,w_create_thread \
                             -Wl,--wrap,mutex_destroy -Wl,--wrap,close -Wl,--wrap,getDefine_Int -Wl,--wrap,OSList_Create \
                             -Wl,--wrap,OSList_SetMaxSize -Wl,--wrap,OSHash_setSize")

LIST(APPEND analysisd_names "test_logtest-config")
LIST(APPEND analysisd_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug2 -Wl,--wrap,get_nproc -Wl,--wrap,cJSON_CreateObject \
                             -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_AddNumberToObject -Wl,--wrap,cJSON_AddItemToObject")

list(LENGTH analysisd_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET analysisd_names ${counter} analysisd_test_name)
    list(GET analysisd_flags ${counter} analysisd_test_flags)

    add_executable(${analysisd_test_name} ${analysisd_test_name}.c)

    target_link_libraries(
        ${analysisd_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ANALYSISD_O
        ${TEST_DEPS}
    )

    if(NOT analysisd_test_flags STREQUAL " ")
        target_link_libraries(
            ${analysisd_test_name}
            ${analysisd_test_flags}
        )
    endif()
    add_test(NAME ${analysisd_test_name} COMMAND ${analysisd_test_name})
endforeach()

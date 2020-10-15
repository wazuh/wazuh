# Generate analysisd library
file(GLOB analysisd_files
    ${SRC_FOLDER}/analysisd/*.o
    ${SRC_FOLDER}/analysisd/cdb/*.o
    ${SRC_FOLDER}/analysisd/alerts/*.o
    ${SRC_FOLDER}/analysisd/decoders/*.o
    ${SRC_FOLDER}/analysisd/output/*.o
    ${SRC_FOLDER}/analysisd/format/*.o
    ${SRC_FOLDER}/analysisd/decoders/plugins/*.o
    ${SRC_FOLDER}/analysisd/compiled_rules/*.o)

add_library(ANALYSISD_O STATIC ${analysisd_files})

include_directories(${SRC_FOLDER}/analysisd)

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

list(APPEND analysisd_names "test_labels")
list(APPEND analysisd_flags "-Wl,--wrap,wdb_get_agent_labels")

list(APPEND analysisd_names "test_mitre")
list(APPEND analysisd_flags "-Wl,--wrap,wdbc_query_ex -Wl,--wrap,_merror -Wl,--wrap,wdbc_query_parse_json")

LIST(APPEND analysisd_names "test_same_different_loop")
LIST(APPEND analysisd_flags "-W")

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

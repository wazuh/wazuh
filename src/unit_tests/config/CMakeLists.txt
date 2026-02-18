# Generate config library
if(${TARGET} STREQUAL "winagent")
    file(GLOB config_files
        ${SRC_FOLDER}/build/config/CMakeFiles/config.dir/src/*.obj)
else()
    file(GLOB config_files
        ${SRC_FOLDER}/build/config/CMakeFiles/config.dir/src/*.c.o)
endif()

add_library(CONFIG_O STATIC ${config_files})

set_source_files_properties(
    ${config_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    CONFIG_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(CONFIG_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate config tests
list(APPEND config_names "test_client-config_validate_ipv6_link_local_interface")
list(APPEND config_flags "-Wl,--wrap,OS_GetHost -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap,syscom_dispatch \
                          -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                          -Wl,--wrap=fim_db_teardown -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}")

if(${TARGET} STREQUAL "server")
    list(APPEND config_names "test_indexer")
    list(APPEND config_flags "-Wl,--wrap,Read_Indexer -Wl,--wrap,get_indexer_cnf ${DEBUG_OP_WRAPPERS}")
    list(APPEND config_names "test_cluster")
    list(APPEND config_flags "${DEBUG_OP_WRAPPERS}")
endif()

# Compiling tests
list(LENGTH config_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET config_names ${counter} test_name)
    list(GET config_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        CONFIG_O
        ${TEST_DEPS}
    )
    if(${TARGET} STREQUAL "winagent")
        target_link_libraries(${test_name} fimdb)
    endif(${TARGET} STREQUAL "winagent")

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

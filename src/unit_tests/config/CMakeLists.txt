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
if(NOT ${TARGET} STREQUAL "manager")
    # The unit-test build does not define CLIENT, but the config library these
    # tests link was built with it for agent targets. A test that needs to know
    # which one it is linked against cannot ask CLIENT, nor anything derived from
    # it such as WAZUHCONFIG, so the target is passed in explicitly.
    add_definitions(-DTEST_AGENT_TARGET)

    list(APPEND config_names "test_client-config_validate_ipv6_link_local_interface")
    list(APPEND config_flags "-Wl,--wrap,OS_GetHost -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap,syscom_dispatch \
                              -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                              -Wl,--wrap=fim_db_teardown -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}")

    # Named test_config-elements, not test_config: CMake target names are global
    # and syscheckd already builds a test_config out of syscheck_config.c.
    list(APPEND config_names "test_config-elements")
    # Same wraps as the sibling tests below: this binary links CONFIG_O, which on
    # winagent drags win_utils.obj and win_service.obj out of DEPENDENCIES_O.
    list(APPEND config_flags "-Wl,--wrap=Start_win32_Syscheck -Wl,--wrap,syscom_dispatch \
                              -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                              -Wl,--wrap=fim_db_teardown -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}")

    list(APPEND config_names "test_client-config_https")
    # The syscheck/dbsync wraps mirror the sibling test above: on winagent this
    # binary pulls win_utils.obj and win_service.obj out of DEPENDENCIES_O, and
    # they reference symbols that live in the syscheckd DLL the tests do not link.
    list(APPEND config_flags "-Wl,--wrap,OS_IsValidIP -Wl,--wrap=Start_win32_Syscheck \
                              -Wl,--wrap,syscom_dispatch -Wl,--wrap=is_fim_shutdown \
                              -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=fim_db_teardown \
                              -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}")
endif()

if(${TARGET} STREQUAL "manager")
    # See the note above on the target name.
    list(APPEND config_names "test_config-elements")
    list(APPEND config_flags "${DEBUG_OP_WRAPPERS}")

    list(APPEND config_names "test_indexer")
    list(APPEND config_flags "-Wl,--wrap,Read_Indexer -Wl,--wrap,get_indexer_cnf ${DEBUG_OP_WRAPPERS}")

    list(APPEND config_names "test_wmodules-config")
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

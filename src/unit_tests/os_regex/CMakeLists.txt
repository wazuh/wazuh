# Generate os_regex library
file(GLOB os_regex_files
    ${SRC_FOLDER}/os_regex/*.o)

add_library(OS_REGEX_O STATIC ${os_regex_files})

set_source_files_properties(
    ${os_regex_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_REGEX_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_REGEX_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate os_regex tests
list(APPEND os_regex_names "test_os_regex")
list(APPEND os_regex_flags "-Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
                            -Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
                            -Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_init -Wl,--wrap=fim_run_integrity \
                            -Wl,--wrap=fim_db_transaction_start -Wl,--wrap=fim_db_transaction_sync_row \
                            -Wl,--wrap=fim_db_transaction_deleted_rows,--wrap=fim_sync_push_msg")

# Compiling tests
list(LENGTH os_regex_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_regex_names ${counter} test_name)
    list(GET os_regex_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_REGEX_O
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

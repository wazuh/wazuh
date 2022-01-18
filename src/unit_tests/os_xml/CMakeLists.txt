# Generate os_xml library
file(GLOB os_xml_files
    ${SRC_FOLDER}/os_xml/*.o)

add_library(OS_XML_O STATIC ${os_xml_files})

set_source_files_properties(
    ${os_xml_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_XML_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_XML_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

add_executable(test_os_xml test_os_xml.c)
target_compile_options(test_os_xml PRIVATE "-Wall")
target_link_libraries(test_os_xml OS_XML_O ${TEST_DEPS})
target_link_libraries(test_os_xml "-Wl,--wrap,getpid -Wl,--wrap=fim_db_file_pattern_search,--wrap=fim_db_remove_path -Wl,--wrap,fim_db_get_path \
-Wl,--wrap=fim_db_file_update,--wrap=fim_db_file_inode_search -Wl,--wrap,fim_db_get_count_file_inode \
-Wl,--wrap=fim_db_get_count_file_entry -Wl,--wrap=fim_db_init -Wl,--wrap=fim_run_integrity \
-Wl,--wrap=fim_db_transaction_start -Wl,--wrap=fim_db_transaction_sync_row \
-Wl,--wrap=fim_db_transaction_deleted_rows,--wrap=fim_sync_push_msg")
add_test(NAME test_os_xml COMMAND test_os_xml)

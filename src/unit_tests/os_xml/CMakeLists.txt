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
target_link_libraries(test_os_xml "")
add_test(NAME test_os_xml COMMAND test_os_xml)
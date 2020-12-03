# Generate config library
file(GLOB config_files
    ${SRC_FOLDER}/config/*.o)

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

# Generate config tests
list(APPEND config_names "test_localfile-config")
list(APPEND config_flags "-Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets \
                          -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fseek \
                          -Wl,--wrap,w_get_attr_val_by_name -Wl,--wrap,_mwarn")


list(LENGTH config_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET config_names ${counter} config_test_name)
    list(GET config_flags ${counter} config_test_flags)

    add_executable(${config_test_name} ${config_test_name}.c)

    target_link_libraries(
        ${config_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        CONFIG_O
        ${TEST_DEPS}
    )

    if(NOT config_test_flags STREQUAL " ")
        target_link_libraries(
            ${config_test_name}
            ${config_test_flags}
        )
    endif()
    add_test(NAME ${config_test_name} COMMAND ${config_test_name})
endforeach()

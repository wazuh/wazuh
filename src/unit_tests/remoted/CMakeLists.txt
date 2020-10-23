# Generate remoted library
file(GLOB remoted_files
    ${SRC_FOLDER}/remoted/*.o)

add_library(REMOTED_O STATIC ${remoted_files})

set_source_files_properties(
    ${remoted_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    REMOTED_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(REMOTED_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate remoted tests
list(APPEND remoted_names "test_manager")
list(APPEND remoted_flags "-W")
list(APPEND remoted_names "test_secure")
list(APPEND remoted_flags "-Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,remove \
                            -Wl,--wrap,_mdebug2 -Wl,--wrap,sleep -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek \
                            -Wl,--wrap,stat -Wl,--wrap,getpid -Wl,--wrap=key_lock_read -Wl,--wrap=key_unlock -Wl,--wrap=time")


list(LENGTH remoted_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET remoted_names ${counter} remoted_test_name)
    list(GET remoted_flags ${counter} remoted_test_flags)

    add_executable(${remoted_test_name} ${remoted_test_name}.c)

    target_link_libraries(
        ${remoted_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        REMOTED_O
        ${TEST_DEPS}
    )

    if(NOT remoted_test_flags STREQUAL " ")
        target_link_libraries(
            ${remoted_test_name}
            ${remoted_test_flags}
        )
    endif()
    add_test(NAME ${remoted_test_name} COMMAND ${remoted_test_name})
endforeach()

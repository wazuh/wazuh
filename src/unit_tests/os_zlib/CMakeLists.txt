# Generate execd library
file(GLOB os_zlib_files
    ${SRC_FOLDER}/os_zlib/*.o)

add_library(OS_ZLIB_O STATIC ${os_zlib_files})

set_source_files_properties(
    ${os_zlib_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_ZLIB_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_ZLIB_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate Execd tests
list(APPEND os_zlib_names "test_os_zlib")
list(APPEND os_zlib_flags " ")


list(LENGTH os_zlib_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_zlib_names ${counter} test_name)
    list(GET os_zlib_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_ZLIB_O
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

# Generate active-response library
file(GLOB active-response_files
    ${SRC_FOLDER}/active-response/*.o)

add_library(ACTIVE-RESPONSE_O STATIC ${active-response_files})

set_source_files_properties(
    ${active-response_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    ACTIVE-RESPONSE_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(ACTIVE-RESPONSE_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate active-response tests
if(NOT ${TARGET} STREQUAL "winagent")
    list(APPEND active-response_names "test_active-response")
    list(APPEND active-response_flags "-Wl,--wrap,getaddrinfo -Wl,--wrap,fcntl")
endif()

list(LENGTH active-response_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET active-response_names ${counter} active-response_test_name)
    list(GET active-response_flags ${counter} active-response_test_flags)

    add_executable(${active-response_test_name} ${active-response_test_name}.c)

    target_link_libraries(
        ${active-response_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ACTIVE-RESPONSE_O
        ${TEST_DEPS}
    )
    if(NOT active-response_test_flags STREQUAL " ")
        target_link_libraries(
            ${active-response_test_name}
            ${active-response_test_flags}
        )
    endif()
    add_test(NAME ${active-response_test_name} COMMAND ${active-response_test_name})
endforeach()
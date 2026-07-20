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
# Generate active-response tests
if(NOT ${TARGET} STREQUAL "winagent")
    list(APPEND active-response_names "test_active-response")
    list(APPEND active-response_flags "-Wl,--wrap,getaddrinfo -Wl,--wrap,fcntl")
endif()

list(APPEND active-response_names "test_firewall_helpers")
list(APPEND active-response_flags " ")

list(LENGTH active-response_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET active-response_names ${counter} active-response_test_name)
    list(GET active-response_flags ${counter} active-response_test_flags)

    add_executable(${active-response_test_name} ${active-response_test_name}.c)

    # firewall_helpers.c is only compiled into the block-ip binaries (see
    # src/active-response/CMakeLists.txt, which is skipped entirely under
    # UNIT_TEST), so compile it directly into this test instead of relying
    # on libwazuh/libwazuh_test.
    if("${active-response_test_name}" STREQUAL "test_firewall_helpers")
        target_sources(${active-response_test_name} PRIVATE
            ${SRC_FOLDER}/active-response/src/helpers/firewall_helpers.c
        )
        target_include_directories(${active-response_test_name} PRIVATE
            ${SRC_FOLDER}/active-response/src/helpers
        )
    endif()

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
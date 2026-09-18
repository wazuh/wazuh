# Generate active-response tests
if(NOT ${TARGET} STREQUAL "winagent")
    list(APPEND active-response_names "test_active-response")
    list(APPEND active-response_flags "-Wl,--wrap,getaddrinfo -Wl,--wrap,fcntl")
endif()

list(APPEND active-response_names "test_firewall_helpers")
list(APPEND active-response_flags " ")

# This guard is unreachable in practice: src/unit_tests/CMakeLists.txt only
# add_subdirectory(active-response)'s under CMAKE_SYSTEM_NAME STREQUAL
# "Linux", so TARGET is never "winagent" by the time this file is processed.
# Kept for consistency with the test_active-response guard above and as a
# defensive default if that top-level condition ever changes.
if(NOT ${TARGET} STREQUAL "winagent")
    list(APPEND active-response_names "test_block_ip_macos")
    list(APPEND active-response_flags "-Wl,--wrap,access -Wl,--wrap,get_binary_path -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,getpid -Wl,--wrap,setup_and_check_message -Wl,--wrap,get_srcip_from_json -Wl,--wrap,send_keys_and_check_message")
endif()

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

    # Same rationale as test_firewall_helpers above: block-ip-macos.c is only
    # ever compiled into the real block-ip binary on a Darwin build, so pull
    # it (and firewall_helpers.c, its own dependency) directly into this test
    # instead of relying on libwazuh/libwazuh_test. `main` is renamed at
    # compile time -- for this one source file only -- so it doesn't collide
    # with this test binary's own cmocka `main`.
    if("${active-response_test_name}" STREQUAL "test_block_ip_macos")
        target_sources(${active-response_test_name} PRIVATE
            ${SRC_FOLDER}/active-response/src/helpers/firewall_helpers.c
            ${SRC_FOLDER}/active-response/src/block-ip-macos.c
        )
        target_include_directories(${active-response_test_name} PRIVATE
            ${SRC_FOLDER}/active-response/src/helpers
            ${SRC_FOLDER}/active-response/include
        )
        set_source_files_properties(${SRC_FOLDER}/active-response/src/block-ip-macos.c PROPERTIES
            COMPILE_DEFINITIONS "__APPLE__;PLATFORM_MACOS=1;main=block_ip_macos_main"
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
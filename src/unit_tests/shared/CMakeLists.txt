
# Tests list and flags
list(APPEND shared_tests_names "test_file_op")
list(APPEND shared_tests_flags "-Wl,--wrap,isChroot -Wl,--wrap,mferror -Wl,--wrap,stat -Wl,--wrap,chmod -Wl,--wrap,File_DateofChange -Wl,--wrap,getpid -Wl,--wrap,unlink -Wl,--wrap,_merror -Wl,--wrap,_minfo -Wl,--wrap,_mwarn -Wl,--wrap,fopen")

list(APPEND shared_tests_names "test_integrity_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_rbtree_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_version_op")
list(APPEND shared_tests_flags "-Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose")

list(APPEND shared_tests_names "test_syscheck_op")
list(APPEND shared_tests_flags "-Wl,--wrap,rmdir_ex -Wl,--wrap,wreaddir -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                        -Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,getpwuid_r -Wl,--wrap,getgrgid \
                         -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,wstr_split \
                         -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP")


# Compiling tests
list(LENGTH shared_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET shared_tests_names ${counter} test_name)
    list(GET shared_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    if(${TARGET} STREQUAL "server")
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            ANALYSISD_O
            ${TEST_DEPS}
        )
    else()
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            ${TEST_DEPS}
        )
    endif()

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

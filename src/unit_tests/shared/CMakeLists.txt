
# Tests list and flags
list(APPEND shared_tests_names "test_file_op")
list(APPEND shared_tests_flags "-Wl,--wrap,isChroot -Wl,--wrap,stat -Wl,--wrap,chmod -Wl,--wrap,File_DateofChange -Wl,--wrap,getpid -Wl,--wrap,unlink -Wl,--wrap,_merror -Wl,--wrap,_minfo -Wl,--wrap,_mwarn -Wl,--wrap,fopen -Wl,--wrap,_mferror -Wl,--wrap,fprintf")

list(APPEND shared_tests_names "test_integrity_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_rbtree_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_string_op")
list(APPEND shared_tests_flags "")

list(APPEND shared_tests_names "test_version_op")
list(APPEND shared_tests_flags "-Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose")

list(APPEND shared_tests_names "test_time_op")
list(APPEND shared_tests_flags " ")

if(${TARGET} STREQUAL "server")
list(APPEND shared_tests_names "test_bzip2_op")
list(APPEND shared_tests_flags "-Wl,--wrap=fopen,--wrap=fread,--wrap=fclose,--wrap=fwrite,--wrap=BZ2_bzWriteOpen,--wrap=BZ2_bzWriteClose64,--wrap=BZ2_bzReadClose,--wrap=BZ2_bzReadOpen,--wrap=BZ2_bzRead,--wrap=BZ2_bzWrite,--wrap=_mdebug2")
endif()

set(SYSCHECK_OP_BASE_FLAGS "-Wl,--wrap,rmdir_ex -Wl,--wrap,wreaddir -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                            -Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,getpwuid_r -Wl,--wrap,getgrgid \
                            -Wl,--wrap,wstr_split -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP,--wrap=sysconf")

list(APPEND shared_tests_names "test_syscheck_op")
if(${TARGET} STREQUAL "winagent")
    # cJSON_CreateArray@0 instead of cJSON_CreateArray since linker will be looking for cdecl forma
    # More info at: (https://devblogs.microsoft.com/oldnewthing/20040108-00/?p=41163)
    list(APPEND shared_tests_flags "${SYSCHECK_OP_BASE_FLAGS} -Wl,--wrap=syscom_dispatch -Wl,--wrap,cJSON_CreateArray@0 -Wl,--wrap,cJSON_CreateObject@0")
else()
    list(APPEND shared_tests_flags "${SYSCHECK_OP_BASE_FLAGS} -Wl,--wrap=cJSON_CreateArray,--wrap=cJSON_CreateObject")
endif()

if(NOT ${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_names "test_audit_op")
list(APPEND shared_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 -Wl,--wrap,audit_send -Wl,--wrap,select -Wl,--wrap,audit_get_reply \
                                -Wl,--wrap,wpopenv -Wl,--wrap,fgets -Wl,--wrap,wpclose -Wl,--wrap,audit_open -Wl,--wrap,audit_add_watch_dir \
                                -Wl,--wrap,audit_update_watch_perms -Wl,--wrap,audit_errno_to_name -Wl,--wrap,audit_rule_fieldpair_data \
                                -Wl,--wrap,audit_add_rule_data -Wl,--wrap,audit_delete_rule_data -Wl,--wrap,audit_close")

list(APPEND shared_tests_names "test_privsep_op")
list(APPEND shared_tests_flags "-Wl,--wrap=sysconf,--wrap=getpwnam_r,--wrap=getgrnam_r")
endif()


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

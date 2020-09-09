
# Tests list and flags
if(NOT ${TARGET} STREQUAL "winagent")
    list(APPEND shared_tests_names "test_file_op")
    set(FILE_OP_BASE_FLAGS "-Wl,--wrap,isChroot,--wrap,stat,--wrap,chmod,--wrap,getpid \
                            -Wl,--wrap,unlink,--wrap,_merror,--wrap,_minfo,--wrap,_mwarn \
                            -Wl,--wrap,fopen,--wrap,_mferror,--wrap,fflush,--wrap,fclose \
                            -Wl,--wrap,fread,--wrap,fseek,--wrap,fwrite,--wrap,remove \
                            -Wl,--wrap,fprintf,--wrap,fgets,--wrap,File_DateofChange \
                            -Wl,--wrap,bzip2_uncompress,--wrap,mdebug1")
    list(APPEND shared_tests_flags "${FILE_OP_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_integrity_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_rbtree_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_string_op")
list(APPEND shared_tests_flags "-Wl,--wrap,_mwarn")

list(APPEND shared_tests_names "test_version_op")
set(VERSION_OP_BASE_FLAGS "-Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fread \
                           -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fprintf -Wl,--wrap,fgets")
list(APPEND shared_tests_flags "${VERSION_OP_BASE_FLAGS}")

list(APPEND shared_tests_names "test_queue_op")
list(APPEND shared_tests_flags "-Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock,--wrap=pthread_cond_wait \
                                -Wl,--wrap=pthread_cond_signal,--wrap=pthread_cond_timedwait")

list(APPEND shared_tests_names "test_agent_op")
list(APPEND shared_tests_flags "-Wl,--wrap,_merror")

list(APPEND shared_tests_names "test_enrollment_op")
set(ENROLLMENT_OP_BASE_FLAGS "-Wl,--wrap=OS_IsValidIP,--wrap=_merror,--wrap=_mwarn,--wrap=check_x509_cert \
                                -Wl,--wrap=_minfo,--wrap=_mdebug1,--wrap=OS_GetHost,--wrap=os_ssl_keys,--wrap=OS_ConnectTCP \
                                -Wl,--wrap=SSL_new,--wrap=SSL_connect,--wrap=SSL_get_error,--wrap=SSL_set_bio \
                                -Wl,--wrap=SSL_write,--wrap=fopen,--wrap=fclose,--wrap=SSL_read \
                                -Wl,--wrap=BIO_new_socket,--wrap=_merror_exit,--wrap=TempFile,--wrap=OS_MoveFile \
                                -Wl,--wrap=fgets")
if(${TARGET} STREQUAL "winagent")
    list(APPEND shared_tests_flags "${ENROLLMENT_OP_BASE_FLAGS}")
else()
    list(APPEND shared_tests_flags "${ENROLLMENT_OP_BASE_FLAGS} -Wl,--wrap=fprintf,--wrap=gethostname,--wrap=getpid")
endif()

list(APPEND shared_tests_names "test_time_op")
list(APPEND shared_tests_flags " ")

if(${TARGET} STREQUAL "server")
list(APPEND shared_tests_names "test_bzip2_op")
list(APPEND shared_tests_flags "-Wl,--wrap=fopen,--wrap=fread,--wrap=fclose,--wrap=fwrite,--wrap=BZ2_bzWriteOpen \
                                -Wl,--wrap=BZ2_bzWriteClose64 -Wl,--wrap=BZ2_bzReadClose,--wrap=BZ2_bzReadOpen \
                                -Wl,--wrap=BZ2_bzRead,--wrap=BZ2_bzWrite,--wrap=_mdebug2,--wrap=fflush \
                                -Wl,--wrap=fgets,--wrap=fprintf,--wrap=fseek,--wrap=remove")

list(APPEND shared_tests_names "test_schedule_scan")
list(APPEND shared_tests_flags "-Wl,--wrap=OS_StrIsNum,--wrap=_merror,--wrap=w_time_delay,--wrap=time,--wrap=_mwarn \
                                -Wl,--wrap=OSRegex_Compile -Wl,--wrap=OSRegex_Execute")
endif()

list(APPEND shared_tests_names "test_syscheck_op")
set(SYSCHECK_OP_BASE_FLAGS "-Wl,--wrap,rmdir_ex -Wl,--wrap,wreaddir -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                            -Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,getpwuid_r -Wl,--wrap,getgrgid \
                            -Wl,--wrap,wstr_split -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                            -Wl,--wrap,sysconf -Wl,--wrap,getpid")
if(${TARGET} STREQUAL "winagent")
    # cJSON_CreateArray@0 instead of cJSON_CreateArray since linker will be looking for cdecl forma
    # More info at: (https://devblogs.microsoft.com/oldnewthing/20040108-00/?p=41163)
    list(APPEND shared_tests_flags "${SYSCHECK_OP_BASE_FLAGS} -Wl,--wrap=syscom_dispatch \
                                    -Wl,--wrap,cJSON_CreateArray@0 -Wl,--wrap,cJSON_CreateObject@0")
else()
    list(APPEND shared_tests_flags "${SYSCHECK_OP_BASE_FLAGS} -Wl,--wrap=cJSON_CreateArray,--wrap=cJSON_CreateObject")
endif()

if(NOT ${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_names "test_audit_op")
list(APPEND shared_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 -Wl,--wrap,audit_send \
                                -Wl,--wrap,select -Wl,--wrap,audit_get_reply -Wl,--wrap,wpopenv -Wl,--wrap,fgets \
                                -Wl,--wrap,wpclose -Wl,--wrap,audit_open -Wl,--wrap,audit_add_watch_dir \
                                -Wl,--wrap,audit_update_watch_perms -Wl,--wrap,audit_errno_to_name \
                                -Wl,--wrap,audit_rule_fieldpair_data -Wl,--wrap,fopen -Wl,--wrap,audit_add_rule_data \
                                -Wl,--wrap,audit_delete_rule_data -Wl,--wrap,audit_close -Wl,--wrap,fclose \
                                -Wl,--wrap,fflush -Wl,--wrap,fprintf -Wl,--wrap,fread -Wl,--wrap,fseek \
                                -Wl,--wrap,fwrite -Wl,--wrap,remove")

list(APPEND shared_tests_names "test_privsep_op")
list(APPEND shared_tests_flags "-Wl,--wrap=sysconf,--wrap=getpwnam_r,--wrap=getgrnam_r,--wrap=getpid")

list(APPEND shared_tests_names "test_mq_op")
list(APPEND shared_tests_flags "-Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,sleep \
                                -Wl,--wrap,_mdebug1 -Wl,--wrap,OS_getsocketsize -Wl,--wrap,_merror")
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

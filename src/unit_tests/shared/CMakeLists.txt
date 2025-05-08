#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Tests list and flags
list(APPEND shared_tests_names "test_list_op")
set(LIST_OP_BASE_FLAGS "-Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,pthread_mutex_lock \
                        -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,pthread_rwlock_unlock \
                        -Wl,--wrap,pthread_rwlock_wrlock ${DEBUG_OP_WRAPPERS}")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${LIST_OP_BASE_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${LIST_OP_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_file_op")
if(NOT ${TARGET} STREQUAL "winagent")
    set(FILE_OP_BASE_FLAGS "-Wl,--wrap,stat,--wrap,chmod,--wrap,getpid,--wrap,wfopen \
                            -Wl,--wrap,unlink,--wrap,fopen,--wrap,fflush,--wrap,fclose \
                            -Wl,--wrap,fread,--wrap,ftell,--wrap,fseek,--wrap,fwrite,--wrap,remove \
                            -Wl,--wrap,fprintf,--wrap,fgets,--wrap,File_DateofChange \
                            -Wl,--wrap,bzip2_uncompress,--wrap,lstat,--wrap,popen \
                            -Wl,--wrap,gzopen,--wrap,gzread,--wrap,gzclose,--wrap,fgetc \
                            -Wl,--wrap,gzeof,--wrap,gzerror,--wrap,gzwrite,--wrap,fgetpos \
                            -Wl,--wrap,realpath,--wrap,getenv,--wrap,atexit ${DEBUG_OP_WRAPPERS} \
                            -Wl,--wrap,merror,--wrap,fseek,--wrap,access")
    list(APPEND shared_tests_flags "${FILE_OP_BASE_FLAGS}")
else()
    list(APPEND shared_tests_flags "-Wl,--wrap,get_windows_file_time_epoch,--wrap,mdebug2 \
                                    -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                    -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                    -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown ${DEBUG_OP_WRAPPERS}")
endif()

list(APPEND shared_tests_names "test_integrity_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_rbtree_op")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND shared_tests_flags " ")
endif()

list(APPEND shared_tests_names "test_validate_op")
set(VALIDATE_OP_FLAGS "-Wl,--wrap,w_expression_match -Wl,--wrap,w_calloc_expression_t \
                       -Wl,--wrap,w_expression_compile -Wl,--wrap,w_free_expression_t \
                       -Wl,--wrap,get_ipv4_numeric -Wl,--wrap,get_ipv6_numeric")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${VALIDATE_OP_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND shared_tests_flags "${VALIDATE_OP_FLAGS}")
endif()

list(APPEND shared_tests_names "test_string_op")
set(STRING_OP_BASE_FLAGS "${DEBUG_OP_WRAPPERS} -Wl,--wrap,syscom_dispatch")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${STRING_OP_BASE_FLAGS} -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${STRING_OP_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_expression")
set(EXPRESSION_BASE_FLAGS "-Wl,--wrap,OS_IsValidIP -Wl,--wrap,OSMatch_Execute -Wl,--wrap,OSRegex_Compile \
                           -Wl,--wrap,OSRegex_Execute -Wl,--wrap,OSRegex_Execute_ex -Wl,--wrap,OSMatch_Compile")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${EXPRESSION_BASE_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${EXPRESSION_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_version_op")
set(VERSION_OP_BASE_FLAGS "-Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,wfopen \
                           -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fprintf -Wl,--wrap,fgets \
                           -Wl,--wrap,fgetpos -Wl,--wrap,fgetc -Wl,--wrap,popen -Wl,--wrap,pclose \
                           -Wl,--wrap,get_binary_path")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${VERSION_OP_BASE_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${VERSION_OP_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_queue_op")
set(QUEUE_OP_BASE_FLAGS "-Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock,--wrap=pthread_cond_wait \
                         -Wl,--wrap=pthread_cond_signal,--wrap=pthread_cond_timedwait")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${QUEUE_OP_BASE_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${QUEUE_OP_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_queue_linked_op")
set(QUEUE_LINKED_OP_BASE_FLAGS  "-Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock,--wrap=pthread_cond_wait \
                                 -Wl,--wrap=pthread_cond_signal")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${QUEUE_LINKED_OP_BASE_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${QUEUE_LINKED_OP_BASE_FLAGS}")
endif()

list(APPEND shared_tests_names "test_agent_op")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,wdb_get_agent_info -Wl,--wrap,_mdebug1 -Wl,--wrap,getpid \
                                -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND shared_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,external_socket_connect \
                                -Wl,--wrap,sleep -Wl,--wrap,strerror -Wl,--wrap,getpid -Wl,--wrap,close \
                                -Wl,--wrap,OS_SendSecureTCPCluster -Wl,--wrap,OS_RecvSecureClusterTCP ${DEBUG_OP_WRAPPERS}")
endif()

list(APPEND shared_tests_names "test_enrollment_op")
set(ENROLLMENT_OP_BASE_FLAGS "-Wl,--wrap=OS_IsValidIP,--wrap=_merror,--wrap=_mwarn,--wrap=check_x509_cert \
                              -Wl,--wrap=_minfo,--wrap=_mdebug1,--wrap=OS_GetHost,--wrap=os_ssl_keys,--wrap=OS_ConnectTCP \
                              -Wl,--wrap=SSL_new,--wrap=SSL_connect,--wrap=SSL_get_error,--wrap=SSL_set_bio \
                              -Wl,--wrap=SSL_write,--wrap=fopen,--wrap=fclose,--wrap=SSL_read \
                              -Wl,--wrap=BIO_new_socket,--wrap=_merror_exit,--wrap=TempFile,--wrap=OS_MoveFile \
                              -Wl,--wrap=fgets -Wl,--wrap,OS_CloseSocket,--wrap=wfopen,--wrap=fflush,--wrap=fgetpos \
                              -Wl,--wrap=fread,--wrap=fseek,--wrap=fwrite,--wrap=remove,--wrap=fgetc -Wl,--wrap,popen \
                              -Wl,--wrap=OS_SetRecvTimeout")

if(${TARGET} STREQUAL "winagent")
    list(APPEND shared_tests_flags "${ENROLLMENT_OP_BASE_FLAGS} -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                    -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                    -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
    list(APPEND shared_tests_flags "${ENROLLMENT_OP_BASE_FLAGS} -Wl,--wrap=fprintf,--wrap=gethostname \
                                    -Wl,--wrap=fgets,--wrap=chmod,--wrap=stat,--wrap=getpid")
endif()

list(APPEND shared_tests_names "test_time_op")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND shared_tests_flags " ")
endif()

list(APPEND shared_tests_names "test_buffer_op")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND shared_tests_flags " ")
endif()

list(APPEND shared_tests_names "test_utf8_op")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags " ")
endif()

list(APPEND shared_tests_names "test_log_builder")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,getDefine_Int -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "-Wl,--wrap,getDefine_Int,--wrap,control_check_connection,--wrap,send,--wrap,recv,--wrap,close \
                                -Wl,--wrap,getpid,--wrap,fcntl")
endif()

list(APPEND shared_tests_names "test_custom_output_search_replace")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND shared_tests_flags " ")
endif()

list(APPEND shared_tests_names "test_binaries_op")
set(BINARIES_OP_BASE_FLAGS "-Wl,--wrap,IsFile -Wl,--wrap,wfopen")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${BINARIES_OP_BASE_FLAGS} -Wl,--wrap,get_windows_file_time_epoch,--wrap,mdebug2 \
                                -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "${BINARIES_OP_BASE_FLAGS} -Wl,--wrap,getenv")
endif()


if(${TARGET} STREQUAL "server")
list(APPEND shared_tests_names "test_bzip2_op")
list(APPEND shared_tests_flags "-Wl,--wrap=fopen,--wrap=fread,--wrap=fclose,--wrap=fwrite,--wrap=BZ2_bzWriteOpen \
                                -Wl,--wrap=BZ2_bzWriteClose -Wl,--wrap=BZ2_bzReadClose,--wrap=BZ2_bzReadOpen \
                                -Wl,--wrap=BZ2_bzRead,--wrap=BZ2_bzWrite,--wrap=_mdebug2,--wrap=fflush \
                                -Wl,--wrap=fgets,--wrap=fprintf,--wrap=fseek,--wrap=remove -Wl,--wrap,fgetpos \
                                -Wl,--wrap=fgetc,--wrap=wfopen -Wl,--wrap,popen")

list(APPEND shared_tests_names "test_schedule_scan")
list(APPEND shared_tests_flags "-Wl,--wrap=OS_StrIsNum,--wrap=_merror,--wrap=w_time_delay,--wrap=time,--wrap=_mwarn \
                                -Wl,--wrap=OSRegex_Compile -Wl,--wrap=OSRegex_Execute -Wl,--wrap,OSMatch_Execute \
                                -Wl,--wrap,OSRegex_Execute_ex")

list(APPEND shared_tests_names "test_rootcheck_op")
set(ROOTCHECK_OP_BASE_FLAGS "-Wl,--wrap=wdbc_query_ex -Wl,--wrap=_merror,--wrap=close")
if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "${ROOTCHECK_OP_BASE_FLAGS}")
else()
list(APPEND shared_tests_flags "${ROOTCHECK_OP_BASE_FLAGS} -Wl,--wrap=getpid")
endif()

list(APPEND shared_tests_names "test_fs_op")
list(APPEND shared_tests_flags " ")

list(APPEND shared_tests_names "test_wazuhdb_op")
list(APPEND shared_tests_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP")
endif()

list(APPEND shared_tests_names "test_syscheck_op")
set(SYSCHECK_OP_BASE_FLAGS "-Wl,--wrap,rmdir_ex -Wl,--wrap,wreaddir -Wl,--wrap,getpwuid_r -Wl,--wrap,w_getgrgid \
                            -Wl,--wrap,wstr_split -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                            -Wl,--wrap,sysconf -Wl,--wrap,win_strerror -Wl,--wrap,wfopen ${DEBUG_OP_WRAPPERS}")
if(${TARGET} STREQUAL "winagent")
    # cJSON_CreateArray@0 instead of cJSON_CreateArray since linker will be looking for cdecl forma
    # More info at: (https://devblogs.microsoft.com/oldnewthing/20040108-00/?p=41163)
    list(APPEND shared_tests_flags "${SYSCHECK_OP_BASE_FLAGS} -Wl,--wrap=syscom_dispatch -Wl,--wrap=is_fim_shutdown \
                                    -Wl,--wrap,cJSON_CreateArray@0 -Wl,--wrap,cJSON_CreateObject@0 -Wl,--wrap=Start_win32_Syscheck")
else()
    list(APPEND shared_tests_flags "${SYSCHECK_OP_BASE_FLAGS} -Wl,--wrap=cJSON_CreateArray,--wrap=cJSON_CreateObject -Wl,--wrap,getpid")
endif()

if(NOT ${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_names "test_json_op")
list(APPEND shared_tests_flags "-Wl,--wrap,w_get_file_content -Wl,--wrap,cJSON_ParseWithOpts \
                                -Wl,--wrap,cJSON_PrintUnformatted -Wl,--wrap,fopen \
                                -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,wfopen \
                                -Wl,--wrap,fflush -Wl,--wrap,fgets \
                                -Wl,--wrap,fgetpos -Wl,--wrap,fgetc \
                                -Wl,--wrap,fread -Wl,--wrap,remove \
                                -Wl,--wrap,fseek -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

list(APPEND shared_tests_names "test_audit_op")
list(APPEND shared_tests_flags "-Wl,--wrap,audit_send -Wl,--wrap,popen \
                                -Wl,--wrap,select -Wl,--wrap,audit_get_reply -Wl,--wrap,wpopenv -Wl,--wrap,fgets \
                                -Wl,--wrap,wpclose -Wl,--wrap,audit_open -Wl,--wrap,audit_add_watch_dir \
                                -Wl,--wrap,audit_update_watch_perms -Wl,--wrap,audit_errno_to_name -Wl,--wrap,wfopen \
                                -Wl,--wrap,audit_rule_fieldpair_data -Wl,--wrap,fopen -Wl,--wrap,audit_add_rule_data \
                                -Wl,--wrap,audit_delete_rule_data -Wl,--wrap,audit_close -Wl,--wrap,fclose \
                                -Wl,--wrap,fflush -Wl,--wrap,fprintf -Wl,--wrap,fread -Wl,--wrap,fseek \
                                -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                                -Wl,--wrap,get_binary_path ${DEBUG_OP_WRAPPERS}")

list(APPEND shared_tests_names "test_privsep_op")
list(APPEND shared_tests_flags "-Wl,--wrap=sysconf,--wrap=getpwnam_r,--wrap=getgrnam_r,--wrap=getpid")

list(APPEND shared_tests_names "test_mq_op")
list(APPEND shared_tests_flags "-Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,sleep \
                                -Wl,--wrap,OS_SendUnix -Wl,--wrap,OS_getsocketsize ${DEBUG_OP_WRAPPERS}")

list(APPEND shared_tests_names "test_remoted_op")
list(APPEND shared_tests_flags "${DEBUG_OP_WRAPPERS}")

endif()

if(${TARGET} STREQUAL "server")
list(APPEND shared_tests_names "test_json-queue")
list(APPEND shared_tests_flags "${DEBUG_OP_WRAPPERS} -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,wfopen \
                                -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite \
                                -Wl,--wrap,remove -Wl,--wrap,fprintf -Wl,--wrap,fgets -Wl,--wrap,w_ftell \
                                -Wl,--wrap,fgetpos -Wl,--wrap,fgetc,--wrap,stat,--wrap,sleep,--wrap,getpid,--wrap,clearerr -Wl,--wrap,popen")

list(APPEND shared_tests_names "test_bqueue")
list(APPEND shared_tests_flags "-Wl,--wrap,_merror -Wl,--wrap,_mdebug2")

endif()

list(APPEND shared_tests_names "test_atomic")

if(${TARGET} STREQUAL "winagent")
list(APPEND shared_tests_flags "-Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                                -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND shared_tests_flags "-Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock")
endif()

list(APPEND shared_tests_names "test_url")
list(APPEND shared_tests_flags "-Wl,--wrap,curl_slist_free_all -Wl,--wrap,curl_easy_cleanup \
                                -Wl,--wrap,curl_easy_init -Wl,--wrap,curl_easy_setopt -Wl,--wrap,wfopen \
                                -Wl,--wrap,curl_slist_append -Wl,--wrap,curl_easy_perform \
                                -Wl,--wrap,curl_easy_getinfo -Wl,--wrap,FileSize ${DEBUG_OP_WRAPPERS}")

list(APPEND shared_tests_names "test_sysinfo_utils")

if(${TARGET} STREQUAL "winagent")
    # cJSON_CreateArray@0 instead of cJSON_CreateArray since linker will be looking for cdecl forma
    # More info at: (https://devblogs.microsoft.com/oldnewthing/20040108-00/?p=41163)
    list(APPEND shared_tests_flags "-Wl,--wrap,so_free_library -Wl,--wrap,so_get_function_sym \
                                -Wl,--wrap,so_get_module_handle -Wl,--wrap,so_get_module_handle_on_path \
                                -Wl,--wrap,sysinfo_os -Wl,--wrap,sysinfo_processes -Wl,--wrap,sysinfo_free_result \
                                -Wl,--wrap,cJSON_GetObjectItem@8 -Wl,--wrap,cJSON_GetStringValue@4 \
                                -Wl,--wrap,syscom_dispatch -Wl,--wrap,Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
    list(APPEND shared_tests_flags "-Wl,--wrap,so_free_library -Wl,--wrap,so_get_function_sym \
                                -Wl,--wrap,so_get_module_handle -Wl,--wrap,so_get_module_handle_on_path \
                                -Wl,--wrap,sysinfo_os -Wl,--wrap,sysinfo_processes -Wl,--wrap,sysinfo_free_result \
                                -Wl,--wrap,cJSON_GetObjectItem -Wl,--wrap,cJSON_GetStringValue")
endif()

list(APPEND shared_tests_names "test_rwlock_op")
list(APPEND shared_tests_flags "${DEBUG_OP_WRAPPERS}")

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
        if(${TARGET} STREQUAL "winagent")
          target_link_libraries(${test_name} fimdb)
        endif(${TARGET} STREQUAL "winagent")
    endif()

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

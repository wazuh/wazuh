include_directories((${SRC_FOLDER}/syscheckd))
include_directories((${SRC_FOLDER}/unit_tests))
include_directories((${SRC_FOLDER}/config))

if(NOT ${TARGET} STREQUAL "winagent")
    # test_audit_healthcheck tests
    add_executable(test_audit_healthcheck test_audit_healthcheck.c)
    target_compile_options(test_audit_healthcheck PRIVATE "-Wall")

    set(AUDIT_HC_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap,audit_add_rule \
                        -Wl,--wrap,pthread_cond_init -Wl,--wrap,pthread_cond_wait -Wl,--wrap,pthread_mutex_lock \
                        -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,CreateThread \
                        -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fgetpos \
                        -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc \
                        -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink -Wl,--wrap,audit_delete_rule \
                        -Wl,--wrap,select -Wl,--wrap,audit_parse")

    target_link_libraries(test_audit_healthcheck SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_healthcheck "${AUDIT_HC_FLAGS}")
    add_test(NAME test_audit_healthcheck COMMAND test_audit_healthcheck)

    # test_syscheck_audit tests
    add_executable(test_audit_rule_handling test_audit_rule_handling.c)
    target_compile_options(test_audit_rule_handling PRIVATE "-Wall")

    set(SYSCHECK_AUDIT_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2,--wrap=_merror,--wrap=_mwarn,--wrap=audit_add_rule\
                              -Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock \
                              -Wl,--wrap=pthread_rwlock_rdlock,--wrap=pthread_rwlock_wrlock,--wrap=pthread_rwlock_unlock \
                              -Wl,--wrap=fopen,--wrap=fclose,--wrap=fflush,--wrap=fgets,--wrap=fgetpos \
                              -Wl,--wrap=fread,--wrap=fseek,--wrap=fwrite,--wrap=remove,--wrap=fgetc \
                              -Wl,--wrap=getpid,--wrap=sleep,--wrap=unlink,--wrap=audit_delete_rule \
                              -Wl,--wrap=select,--wrap=audit_parse,--wrap=audit_get_rule_list,--wrap=audit_close \
                              -Wl,--wrap=search_audit_rule,--wrap=audit_open")

    target_link_libraries(test_audit_rule_handling SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_rule_handling "${SYSCHECK_AUDIT_FLAGS}")
    add_test(NAME test_audit_rule_handling COMMAND test_audit_rule_handling)

    # test_syscheck_audit tests
    add_executable(test_syscheck_audit test_syscheck_audit.c)
    target_compile_options(test_syscheck_audit PRIVATE "-Wall")

    set(SYSCHECK_AUDIT_FLAGS "-Wl,--wrap,_mdebug1,--wrap,_mdebug2 -Wl,--wrap,_merror -Wl,--wrap,_mwarn \
                              -Wl,--wrap,_minfo -Wl,--wrap,pthread_cond_wait -Wl,--wrap,pthread_mutex_lock \
                              -Wl,--wrap,openproc -Wl,--wrap,readproc -Wl,--wrap,freeproc -Wl,--wrap,FOREVER \
                              -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,audit_add_rule -Wl,--wrap,audit_restart  \
                              -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,closeproc  -Wl,--wrap,recv -Wl,--wrap,IsDir \
                              -Wl,--wrap,IsLink -Wl,--wrap,IsFile -Wl,--wrap,IsSocket -Wl,--wrap,fprintf \
                              -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fgetpos \
                              -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc \
                              -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink -Wl,--wrap,audit_delete_rule \
                              -Wl,--wrap,select -Wl,--wrap,audit_parse -Wl,--wrap,symlink -Wl,--wrap,SendMSG \
                              -Wl,--wrap,audit_get_rule_list -Wl,--wrap,fim_audit_reload_rules -Wl,--wrap,search_audit_rule")

    target_link_libraries(test_syscheck_audit SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_syscheck_audit "${SYSCHECK_AUDIT_FLAGS}")
    add_test(NAME test_syscheck_audit COMMAND test_syscheck_audit)

    # test_audit_parse tests
    add_executable(test_audit_parse test_audit_parse.c)
    target_compile_options(test_audit_parse PRIVATE "-Wall")

    set(AUDIT_PARSE_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap=_mwarn -Wl,--wrap=_minfo -Wl,--wrap,_merror \
                           -Wl,--wrap,audit_add_rule -Wl,--wrap,pthread_mutex_lock \
                           -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush \
                           -Wl,--wrap,fgets -Wl,--wrap,fgetpos -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite\
                           -Wl,--wrap,remove -Wl,--wrap,fgetc -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink \
                           -Wl,--wrap,audit_delete_rule -Wl,--wrap,realpath -Wl,--wrap,atexit -Wl,--wrap,audit_open\
                           -Wl,--wrap,get_user -Wl,--wrap,get_group -Wl,--wrap,readlink -Wl,--wrap,audit_get_rule_list \
                           -Wl,--wrap,SendMSG -Wl,--wrap,fim_whodata_event -Wl,--wrap,search_audit_rule \
                           -Wl,--wrap,audit_close -Wl,--wrap,fim_manipulated_audit_rules \
                           -Wl,--wrap,fim_audit_reload_rules -Wl,--wrap,remove_audit_rule_syscheck")

    target_link_libraries(test_audit_parse SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_parse "${AUDIT_PARSE_FLAGS}")
    add_test(NAME test_audit_parse COMMAND test_audit_parse)
else()
    add_executable(test_win_whodata test_win_whodata.c)
    target_compile_options(test_win_whodata PRIVATE "-Wall")
    set(WIN_WHODATA_FLAGS "-Wl,--wrap,_mdebug2 -Wl,--wrap,_merror -Wl,--wrap,_mdebug1 -Wl,--wrap,_mwarn \
                           -Wl,--wrap,wstr_replace -Wl,--wrap,SendMSG -Wl,--wrap,OSHash_Add_ex \
                           -Wl,--wrap,free_whodata_event -Wl,--wrap,IsFile -Wl,--wrap=remove \
                           -Wl,--wrap,wm_exec -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,atexit \
                           -Wl,--wrap,OSHash_Delete_ex -Wl,--wrap,_mterror -Wl,--wrap,check_path_type \
                           -Wl,--wrap,_minfo -Wl,--wrap,OSHash_Create -Wl,--wrap,pthread_rwlock_unlock \
                           -Wl,--wrap,OSHash_SetFreeDataPointer -Wl,--wrap,fim_whodata_event \
                           -Wl,--wrap,fim_checker -Wl,--wrap,OSHash_Get -Wl,--wrap,os_random \
                           -Wl,--wrap,convert_windows_string -Wl,--wrap,OSHash_Get_ex -Wl,--wrap,FOREVER \
                           -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,fprintf \
                           -Wl,--wrap,fgets -Wl,--wrap,wstr_split -Wl,--wrap,pthread_rwlock_wrlock \
                           -Wl,--wrap,fgetpos -Wl,--wrap,fgetc -Wl,--wrap,getDefine_Int")
    target_link_libraries(test_win_whodata SYSCHECK_EVENT_O ${TEST_EVENT_DEPS})

    target_link_libraries(test_win_whodata "${WIN_WHODATA_FLAGS}")
    add_test(NAME test_win_whodata COMMAND test_win_whodata)
endif()

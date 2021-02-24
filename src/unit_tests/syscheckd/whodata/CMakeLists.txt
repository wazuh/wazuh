include_directories((${SRC_FOLDER}/syscheckd))
include_directories((${SRC_FOLDER}/unit_tests))
include_directories((${SRC_FOLDER}/config))

if(NOT ${TARGET} STREQUAL "winagent")
    # test_audit_healthcheck tests
    add_executable(test_audit_healthcheck test_audit_healthcheck.c)
    target_compile_options(test_audit_healthcheck PRIVATE "-Wall")

    set(AUDIT_HC_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap,audit_add_rule -Wl,--wrap,recv \
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

    set(SYSCHECK_AUDIT_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap,_merror-Wl,--wrap,audit_add_rule\
                              -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                              -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fgetpos \
                              -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc \
                              -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink -Wl,--wrap,audit_delete_rule \
                              -Wl,--wrap,select -Wl,--wrap,audit_parse -Wl,--wrap,audit_get_rule_list \
                              -Wl,--wrap,search_audit_rule -Wl,--wrap,audit_open -Wl,--wrap,getDefine_Int")

    target_link_libraries(test_audit_rule_handling SYSCHECK_O ${TEST_DEPS})

    target_link_libraries(test_audit_rule_handling "${SYSCHECK_AUDIT_FLAGS}")
    add_test(NAME test_audit_rule_handling COMMAND test_audit_rule_handling)

    # test_syscheck_audit tests
    # add_executable(test_syscheck_audit test_syscheck_audit.c)
    # target_compile_options(test_syscheck_audit PRIVATE "-Wall")

    # set(SYSCHECK_AUDIT_FLAGS "-Wl,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap,audit_add_rule -Wl,--wrap,recv \
    #                           -Wl,--wrap,pthread_cond_init -Wl,--wrap,pthread_cond_wait -Wl,--wrap,pthread_mutex_lock \
    #                           -Wl,--wrap,pthread_mutex_unlock -Wl,--wrap,CreateThread \
    #                           -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fgetpos \
    #                           -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fgetc \
    #                           -Wl,--wrap,getpid -Wl,--wrap,sleep -Wl,--wrap,unlink -Wl,--wrap,audit_delete_rule \
    #                           -Wl,--wrap,select -Wl,--wrap,audit_parse")

    # target_link_libraries(test_syscheck_audit SYSCHECK_O ${TEST_DEPS})

    # target_link_libraries(test_syscheck_audit "${SYSCHECK_AUDIT_FLAGS}")
    # add_test(NAME test_syscheck_audit COMMAND test_syscheck_audit)

endif()

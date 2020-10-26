include_directories((${SRC_FOLDER}/syscheckd))
include_directories((${SRC_FOLDER}/unit_tests))
include_directories((${SRC_FOLDER}/config))

# fim_db.c tests
add_executable(test_fim_db test_fim_db.c)

target_compile_options(test_fim_db PRIVATE "-Wall")

set(FIM_DB_BASE_FLAGS "-Wl,--wrap=w_is_file,--wrap=remove,--wrap=sqlite3_open_v2,--wrap=sqlite3_exec,--wrap=_merror \
                       -Wl,--wrap=sqlite3_prepare_v2,--wrap=sqlite3_step,--wrap=sqlite3_finalize \
                       -Wl,--wrap=sqlite3_close_v2 -Wl,--wrap=chmod,--wrap=sqlite3_free,--wrap=sqlite3_reset \
                       -Wl,--wrap=sqlite3_clear_bindings -Wl,--wrap=sqlite3_errmsg,--wrap=sqlite3_bind_int \
                       -Wl,--wrap=sqlite3_bind_text,--wrap=sqlite3_column_int -Wl,--wrap=sqlite3_column_text \
                       -Wl,--wrap=fim_send_sync_msg,--wrap=dbsync_state_msg -Wl,--wrap=fim_entry_json \
                       -Wl,--wrap=sqlite3_last_insert_rowid,--wrap=EVP_DigestUpdate \
                       -Wl,--wrap=fim_configuration_directory,--wrap=fim_json_event,--wrap=send_syscheck_msg \
                       -Wl,--wrap=delete_target_file,--wrap=_minfo,--wrap=_mdebug1,--wrap=_mdebug2 -Wl,--wrap=fseek \
                       -Wl,--wrap=fclose,--wrap=fopen,--wrap=getpid,--wrap=fflush -Wl,--wrap=wstr_escape_json \
                       -Wl,--wrap=sqlite3_bind_int64,--wrap=sqlite3_column_int64 -Wl,--wrap=fread,--wrap=fwrite \
                       -Wl,--wrap=fprintf,--wrap=fgets,--wrap=stat,--wrap=wstr_split,--wrap=os_random \
                       -Wl,--wrap=DirSize,--wrap=IsDir")

target_link_libraries(test_fim_db SYSCHECK_O ${TEST_DEPS})
if(${TARGET} STREQUAL "agent")
    list(APPEND syscheckd_tests_flags "")
    target_link_libraries(test_fim_db "${FIM_DB_BASE_FLAGS} -Wl,--wrap=isChroot -Wl,--wrap=usleep,--wrap=time")
elseif(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_fim_db "${FIM_DB_BASE_FLAGS}")
else()
    target_link_libraries(test_fim_db "${FIM_DB_BASE_FLAGS} -Wl,--wrap=usleep,--wrap=time")
endif()

add_test(NAME test_fim_db COMMAND test_fim_db)

# fim_db_registries.c tests
if(${TARGET} STREQUAL "winagent")
    add_executable(test_fim_db_registries test_fim_db_registries.c)

    target_compile_options(test_fim_db_registries PRIVATE "-Wall")

    target_link_libraries(test_fim_db_registries SYSCHECK_O ${TEST_DEPS})
    target_link_libraries(test_fim_db_registries "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn,--wrap=sqlite3_step")

    add_test(NAME test_fim_db_registries COMMAND test_fim_db_registries)
endif()

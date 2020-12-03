include_directories((${SRC_FOLDER}/syscheckd))
include_directories((${SRC_FOLDER}/unit_tests))
include_directories((${SRC_FOLDER}/config))

# fim_db.c tests
add_executable(test_fim_db test_fim_db.c)

target_compile_options(test_fim_db PRIVATE "-Wall")

set(FIM_DB_BASE_FLAGS "-Wl,--wrap=w_is_file,--wrap=remove,--wrap=sqlite3_open_v2,--wrap=sqlite3_exec,--wrap=_merror \
                       -Wl,--wrap=sqlite3_prepare_v2,--wrap=sqlite3_step,--wrap=sqlite3_finalize \
                       -Wl,--wrap=sqlite3_close_v2,--wrap=chmod,--wrap=sqlite3_free,--wrap=sqlite3_reset \
                       -Wl,--wrap=sqlite3_clear_bindings,--wrap=sqlite3_errmsg,--wrap=sqlite3_bind_int \
                       -Wl,--wrap=sqlite3_bind_text,--wrap=sqlite3_column_int,--wrap=sqlite3_column_text \
                       -Wl,--wrap=EVP_DigestUpdate,--wrap=_minfo,--wrap=_mdebug1,--wrap=_mdebug2,--wrap=fseek \
                       -Wl,--wrap=fclose,--wrap=fopen,--wrap=getpid,--wrap=fflush,--wrap=wstr_escape_json \
                       -Wl,--wrap=sqlite3_column_int64,--wrap=fread,--wrap=fwrite,--wrap=_mwarn \
                       -Wl,--wrap=fprintf,--wrap=fgets,--wrap=stat,--wrap=wstr_split,--wrap=os_random \
                       -Wl,--wrap=DirSize,--wrap=IsDir,--wrap=sqlite3_column_count,--wrap=getDefine_Int,--wrap=wfopen")

target_link_libraries(test_fim_db SYSCHECK_O ${TEST_DEPS} fim_shared)
if(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_fim_db "${FIM_DB_BASE_FLAGS}")
else()
    target_link_libraries(test_fim_db "${FIM_DB_BASE_FLAGS} -Wl,--wrap=usleep,--wrap=time")
endif()

add_test(NAME test_fim_db COMMAND test_fim_db)

# fim_db_files.c tests
add_executable(test_fim_db_files test_fim_db_files.c)

target_compile_options(test_fim_db_files PRIVATE "-Wall")

target_link_libraries(test_fim_db_files SYSCHECK_O ${TEST_DEPS} fim_shared)

set(FIM_DB_FILES_LINUX_FLAGS "-Wl,--wrap=isChroot -Wl,--wrap=usleep,--wrap=time,--wrap=sqlite3_bind_int64 \
                              -Wl,--wrap=sqlite3_last_insert_rowid,--wrap=SendMSG,--wrap=rmdir_ex,--wrap=opendir \
                              -Wl,--wrap=readdir,--wrap=closedir")

set(FIM_DB_FILES_WINDOWS_FLAG "-Wl,--wrap=sqlite3_last_insert_rowid,--wrap=SendMSG,,--wrap=rmdir_ex,--wrap=opendir \
                               -Wl,--wrap=readdir,--wrap=closedir")

if(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_fim_db_files ${FIM_DB_BASE_FLAGS} ${FIM_DB_FILES_WINDOWS_FLAG})
else()
    target_link_libraries(test_fim_db_files ${FIM_DB_BASE_FLAGS} ${FIM_DB_FILES_LINUX_FLAGS})
endif()

add_test(NAME test_fim_db_files COMMAND test_fim_db_files)

# fim_db_registries.c tests
if(${TARGET} STREQUAL "winagent")
    add_executable(test_fim_db_registries test_fim_db_registries.c)

    target_compile_options(test_fim_db_registries PRIVATE "-Wall")

    target_link_libraries(test_fim_db_registries SYSCHECK_O ${TEST_DEPS})
    target_link_libraries(test_fim_db_registries "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn,--wrap=sqlite3_step")

    add_test(NAME test_fim_db_registries COMMAND test_fim_db_registries)
endif()

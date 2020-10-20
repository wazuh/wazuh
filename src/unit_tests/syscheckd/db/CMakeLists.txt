include_directories((${SRC_FOLDER}/syscheckd))

# fim_db_registries.c tests
add_executable(test_fim_db_registries test_fim_db_registries.c)

target_compile_options(test_fim_db_registries PRIVATE "-Wall")

target_link_libraries(test_fim_db_registries SYSCHECK_O ${TEST_DEPS})
target_link_libraries(test_fim_db_registries "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn,--wrap=sqlite3_step")

add_test(NAME test_fim_db_registries COMMAND test_fim_db_registries)

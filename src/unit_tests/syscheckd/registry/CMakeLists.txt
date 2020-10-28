include_directories((${SRC_FOLDER}/syscheckd))

# registry.c tests
add_executable(test_registry test_registry.c)

target_compile_options(test_registry PRIVATE "-Wall")

target_link_libraries(test_registry SYSCHECK_O ${TEST_DEPS})
target_link_libraries(test_registry "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn
                                     -Wl,--wrap=send_syscheck_msg,--wrap=os_random")

add_test(NAME test_registry COMMAND test_registry)

# events.c tests
add_executable(test_events test_events.c)

target_compile_options(test_events PRIVATE "-Wall")

target_link_libraries(test_events SYSCHECK_O ${TEST_DEPS})
target_link_libraries(test_events "-Wl,--wrap=_mdebug2,--wrap=_mdebug1,--wrap=_merror,--wrap=_mwarn")

add_test(NAME test_events COMMAND test_events)

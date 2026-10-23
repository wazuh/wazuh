# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Generate wmodules library
file(GLOB_RECURSE wmodules_files
    ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*.c.o)
list(REMOVE_ITEM wmodules_files ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main.c.o)

add_library(WMODULES_O STATIC ${wmodules_files})

set_source_files_properties(
    ${wmodules_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    WMODULES_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(WMODULES_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate wmodules tests
list(APPEND wmodules_names "test_wmodules")
list(APPEND wmodules_flags "-Wl,--wrap,w_query_agentd -Wl,--wrap,_merror -Wl,--wrap,_mdebug1 \
                            -Wl,--wrap,OS_ConnectUnixDomain")

list(APPEND wmodules_names "test_wmcom")
list(APPEND wmodules_flags "-Wl,--wrap,getModulesConfig -Wl,--wrap,getModulesInternalOptions \
                            -Wl,--wrap,w_query_agentd -Wl,--wrap,_merror -Wl,--wrap,_mdebug1")

# The shutdown sequence and wm_setup() live in main.c, which WMODULES_O leaves out: the test includes it. It is built
# for both targets (the manager without CLIENT, additionally wrapping the runtime's begin_shutdown/shutdown; the agent
# additionally wrapping wm_setup()'s collaborators for the -t test).
set(wm_main_wrap "-Wl,--wrap,clock_gettime -Wl,--wrap,nanosleep -Wl,--wrap,exit -Wl,--wrap,pthread_timedjoin_np \
                  -Wl,--wrap,write -Wl,--wrap,startup_gate_wait_for_ready -Wl,--wrap,_merror -Wl,--wrap,_mdebug1")
if(${TARGET} STREQUAL "manager")
    set(wm_main_wrap "${wm_main_wrap} -Wl,--wrap,wm_indexer_runtime_begin_shutdown \
                      -Wl,--wrap,wm_indexer_runtime_shutdown -Wl,--wrap,wm_kill_children -Wl,--wrap,DeletePID")
else()
    set(wm_main_wrap "${wm_main_wrap} -Wl,--wrap,wm_config -Wl,--wrap,wm_check -Wl,--wrap,w_read_agent_batch \
                      -Wl,--wrap,getDefine_Int_default -Wl,--wrap,Privsep_GetGroup -Wl,--wrap,Privsep_SetGroup \
                      -Wl,--wrap,CreatePID -Wl,--wrap,wm_children_pool_init")
endif()
list(APPEND wmodules_names "test_wm_main")
list(APPEND wmodules_flags "${wm_main_wrap}")

# The task manager's reader of the sections it borrows (`global`, `remote`): a refusal is reported to
# wm_config(), which makes `-t` fail. Manager only.
if(${TARGET} STREQUAL "manager")
    list(APPEND wmodules_names "test_wm_task_manager_read_json")
    list(APPEND wmodules_flags "-Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1")

    # The C side of the indexer runtime bridge (manager only: the agent's source is a stub).
    list(APPEND wmodules_names "test_wm_indexer_runtime")
    list(APPEND wmodules_flags "-Wl,--wrap,wfopen -Wl,--wrap,so_get_module_handle -Wl,--wrap,so_get_function_sym \
                                -Wl,--wrap,so_free_library -Wl,--wrap,_mterror -Wl,--wrap,_mtinfo \
                                -Wl,--wrap,_mtdebug1 -Wl,--wrap,_mtwarn")
endif()

# The listener loop, in its own binary so that wrapping close and accept does not reach the
# other wmcom tests.
list(APPEND wmodules_names "test_wmcom_main")
list(APPEND wmodules_flags "-Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,wm_select_interruptible \
                            -Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,OS_SetRecvTimeout \
                            -Wl,--wrap,OS_SetSendTimeout -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP \
                            -Wl,--wrap,w_query_agentd -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1")

# Compilig tests
list(LENGTH wmodules_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wmodules_names ${counter} test_name)
    list(GET wmodules_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        WMODULES_O
        ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

if(TARGET test_wm_main AND ${TARGET} STREQUAL "agent")
    # main.c has to be built as CLIENT, like the agent's WMODULES_O objects (the manager's is not).
    target_compile_definitions(test_wm_main PRIVATE CLIENT)
endif()

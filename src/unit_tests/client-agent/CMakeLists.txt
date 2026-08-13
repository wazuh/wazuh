# Generate client-agent library
if(${TARGET} STREQUAL "winagent")
  # On winagent, agentd objects are already in DEPENDENCIES_O (winagent.cmake).
  # Creating a separate CLIENT-AGENT library from the same objects would cause
  # duplicate globals (e.g. agent_state), leading to test failures where the
  # test modifies one copy but production code reads the other.
else()
  file(GLOB client-agent_files
       ${SRC_FOLDER}/build/client-agent/CMakeFiles/agentd_lib.dir/src/*.o)
  list(REMOVE_ITEM client-agent_files ${SRC_FOLDER}/build/client-agent/CMakeFiles/agentd_lib.dir/src/main.c.o)
endif()

if(NOT ${TARGET} STREQUAL "winagent")
list(REMOVE_ITEM client-agent_files ${SRC_FOLDER}/client-agent/main.o)

add_library(CLIENT-AGENT STATIC ${client-agent_files} ${CMAKE_CURRENT_SOURCE_DIR}/https_client_stubs.c)

set_source_files_properties(
    ${client-agent_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    CLIENT-AGENT
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(CLIENT-AGENT ${WAZUHLIB} ${WAZUHEXT} -lpthread)
endif()

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/build/bin)
endif(${TARGET} STREQUAL "winagent")

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate agentd tests
list(APPEND client-agent_names "test_start_agent")
set(START_AGENT_BASE_FLAGS "-Wl,--wrap,w_rotate_log -Wl,--wrap,getDefine_Int -Wl,--wrap,getDefine_Int_default \
                            -Wl,--wrap,w_https_client_submit_event -Wl,--wrap,getpid ${DEBUG_OP_WRAPPERS} \
                            -Wl,--wrap=is_fim_shutdown -Wl,--wrap=fim_db_teardown \
                            -Wl,--wrap=_imp__dbsync_initialize \
                            -Wl,--wrap,metadata_provider_update -Wl,--wrap,get_unix_version -Wl,--wrap,get_win_version -Wl,--wrap,free_osinfo")
if(${TARGET} STREQUAL "winagent")
    list(APPEND client-agent_flags "${START_AGENT_BASE_FLAGS} -Wl,--wrap,os_random -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap,w_query_agentd")
else()
    list(APPEND client-agent_flags "${START_AGENT_BASE_FLAGS}")
endif()

list(APPEND client-agent_names "test_agentd_state")
if(${TARGET} STREQUAL "winagent")
    # cJSON_func@x instead of cJSON_func since linker will be looking for cdecl forma
    # More info at: (https://devblogs.microsoft.com/oldnewthing/20040108-00/?p=41163)
    list(APPEND client-agent_flags "-Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                                    -Wl,--wrap,cJSON_CreateObject@0 -Wl,--wrap,cJSON_AddNumberToObject@16 \
                                    -Wl,--wrap,cJSON_AddItemToObject@12 -Wl,--wrap,cJSON_AddStringToObject@12 \
                                    -Wl,--wrap,cJSON_Delete@4 -Wl,--wrap,strftime -Wl,--wrap=syscom_dispatch \
                                    -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=is_fim_shutdown -Wl,--wrap=fim_db_teardown \
                                    -Wl,--wrap=_imp__dbsync_initialize \
                                    -Wl,--wrap,cJSON_PrintUnformatted@4 \
                                    -Wl,--wrap,cJSON_AddBoolToObject@12 -Wl,--wrap,w_query_agentd -Wl,--enable-stdcall-fixup ${DEBUG_OP_WRAPPERS}")
else()
    list(APPEND client-agent_flags "-Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                                    -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,cJSON_AddNumberToObject -Wl,--wrap,strftime \
                                    -Wl,--wrap,cJSON_AddItemToObject -Wl,--wrap,cJSON_AddStringToObject -Wl,--wrap,cJSON_Delete \
                                    -Wl,--wrap,cJSON_PrintUnformatted \
                                    -Wl,--wrap,cJSON_AddBoolToObject ${DEBUG_OP_WRAPPERS}")
endif()

list(APPEND client-agent_names "test_agcom")
if(${TARGET} STREQUAL "winagent")
list(APPEND client-agent_flags "-Wl,--wrap,getAgentConfig \
                                -Wl,--wrap,getLabelsConfig -Wl,--wrap,getAgentInternalOptions \
                                -Wl,--wrap,getAntiTamperingConfig -Wl,--wrap,w_agentd_state_get \
                                -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck \
                                -Wl,--wrap=is_fim_shutdown -Wl,--wrap=fim_db_teardown \
                                -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=_imp__rsync_initialize")
else()
list(APPEND client-agent_flags "-Wl,--wrap,getAgentConfig \
                                -Wl,--wrap,getLabelsConfig -Wl,--wrap,getAgentInternalOptions \
                                -Wl,--wrap,getAntiTamperingConfig -Wl,--wrap,w_agentd_state_get")
endif()

if(${TARGET} STREQUAL "agent")
list(APPEND client-agent_names "test_agentd")
list(APPEND client-agent_flags "-Wl,--wrap,wurl_free_response -Wl,--wrap,wurl_http_request \
                                -Wl,--wrap,w_https_client_start -Wl,--wrap,w_https_client_stop \
                                -Wl,--wrap,getDefine_Int -Wl,--wrap,getDefine_Int_default \
                                -Wl,--wrap,OS_IsValidIP ${DEBUG_OP_WRAPPERS}")

list(APPEND client-agent_names "test_startup_gate")
list(APPEND client-agent_flags "-Wl,--wrap,OS_SHA256_File ${DEBUG_OP_WRAPPERS}")

list(APPEND client-agent_names "test_agent_ssl_ca")
list(APPEND client-agent_flags "-Wl,--wrap,w_is_file ${DEBUG_OP_WRAPPERS}")

list(APPEND client-agent_names "test_https_client_bridge")
list(APPEND client-agent_flags "-Wl,--wrap,wurl_free_response -Wl,--wrap,wurl_http_request \
                                -Wl,--wrap,hc_create -Wl,--wrap,hc_start -Wl,--wrap,hc_destroy \
                                -Wl,--wrap,hc_set_agent_key -Wl,--wrap,hc_submit_event \
                                -Wl,--wrap,hc_set_config_hash \
                                -Wl,--wrap,try_enroll_to_server \
                                -Wl,--wrap,CreateThread -Wl,--wrap,sleep -Wl,--wrap,getpid \
                                -Wl,--wrap,w_agentd_state_update -Wl,--wrap,getDefine_Int \
                                -Wl,--wrap,getDefine_Int_default \
                                -Wl,--wrap,w_copy_file -Wl,--wrap,UnmergeFiles -Wl,--wrap,cldir_ex_ignore \
                                -Wl,--wrap,wfopen \
                                -Wl,--wrap,verifyRemoteConf -Wl,--wrap,reloadAgent \
                                -Wl,--wrap,w_agentd_populate_metadata \
                                -Wl,--wrap,startup_gate_release_from_https_apply \
                                -Wl,--wrap,startup_gate_is_ready \
                                -Wl,--wrap,os_delwait -Wl,--wrap,os_setwait \
                                -Wl,--wrap,OS_SHA256_File \
                                -Wl,--wrap,task_registry_check_and_record \
                                -Wl,--wrap,vd_offset_client_observe \
                                -Wl,--wrap,vd_offset_client_clear_pending \
                                -Wl,--wrap,restartAgent \
                                -Wl,--wrap,OS_SendUnix -Wl,--wrap,w_ref_parent_folder \
                                -Wl,--wrap,OS_ConnectUnixDomain \
                                -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,OS_RecvSecureTCP \
                                ${DEBUG_OP_WRAPPERS}")
endif()

# The aggregator reaches the daemons differently per platform, so each side
# wraps what it actually calls: sockets on POSIX, the dispatchers in-process on
# Windows. The assertions in the test are shared.
list(APPEND client-agent_names "test_agent_report")
if(${TARGET} STREQUAL "winagent")
list(APPEND client-agent_flags "-Wl,--wrap,agcom_dispatch -Wl,--wrap,syscom_dispatch \
                                -Wl,--wrap,lccom_dispatch -Wl,--wrap,wmcom_dispatch \
                                -Wl,--wrap,wcom_dispatch -Wl,--wrap,startup_gate_is_settled \
                                -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=is_fim_shutdown \
                                -Wl,--wrap=fim_db_teardown -Wl,--wrap=_imp__dbsync_initialize \
                                -Wl,--wrap=_imp__rsync_initialize ${DEBUG_OP_WRAPPERS}")
else()
list(APPEND client-agent_flags "-Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP \
                                -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,startup_gate_is_settled \
                                ${DEBUG_OP_WRAPPERS}")
endif()

list(LENGTH client-agent_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET client-agent_names ${counter} client-agent_test_name)
    list(GET client-agent_flags ${counter} client-agent_test_flags)

    add_executable(${client-agent_test_name} ${client-agent_test_name}.c)

    if(${TARGET} STREQUAL "winagent")
        # On winagent, agentd objects come from DEPENDENCIES_O (in TEST_DEPS)
        target_link_libraries(
            ${client-agent_test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            ${TEST_DEPS}
        )
        target_link_libraries(${client-agent_test_name} fimdb)
    else()
        target_link_libraries(
            ${client-agent_test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            CLIENT-AGENT
            ${TEST_DEPS}
        )
    endif()

    if(NOT client-agent_test_flags STREQUAL " ")
        target_link_libraries(
            ${client-agent_test_name}
            ${client-agent_test_flags}
        )
    endif()
    add_test(NAME ${client-agent_test_name} COMMAND ${client-agent_test_name})
endforeach()

if(TARGET test_https_client_bridge)
    # https_client.h (the module's C ABI) isn't on the global include path.
    target_include_directories(test_https_client_bridge PRIVATE ${SRC_FOLDER}/client-agent/https_client/include)
endif()

# Component test for the durable dedup + IPC round-trip: wires the
# REAL client (task_registry_client.c, via CLIENT-AGENT, unwrapped) to the
# REAL server-side dispatch chain (wmcom_dispatch -> wm_module_query ->
# wm_agent_info_query -> the real TaskIdRegistry) over a REAL AF_UNIX
# socket, all in one process. See test_task_registry_ipc_component.cpp's
# file banner for exactly what is real vs. test harness. Needs real
# sockets/threads (POSIX) and gtest; agent target, not winagent.
if(${TARGET} STREQUAL "agent" AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  enable_language(CXX)

  file(GLOB_RECURSE task_registry_ipc_wm_objs
       ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*.c.o)
  list(REMOVE_ITEM task_registry_ipc_wm_objs
       ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main.c.o)

  add_library(TASK_REGISTRY_IPC_WM_O STATIC ${task_registry_ipc_wm_objs})
  set_source_files_properties(
      ${task_registry_ipc_wm_objs}
      PROPERTIES
      EXTERNAL_OBJECT true
      GENERATED true)
  set_target_properties(TASK_REGISTRY_IPC_WM_O PROPERTIES LINKER_LANGUAGE C)
  target_link_libraries(TASK_REGISTRY_IPC_WM_O ${WAZUHLIB} ${WAZUHEXT} -lpthread -ldl)

  link_directories(${SRC_FOLDER}/external/googletest/lib/)

  add_executable(test_task_registry_ipc_component test_task_registry_ipc_component.cpp)
  target_include_directories(
      test_task_registry_ipc_component
      PRIVATE ${SRC_FOLDER}/external/googletest/googletest/include/
              ${SRC_FOLDER}/wazuh_modules/agent_info/include
              ${SRC_FOLDER}/wazuh_modules/src)
  target_link_libraries(
      test_task_registry_ipc_component
      debug gtestd
      debug gtest_maind
      optimized gtest
      optimized gtest_main
      CLIENT-AGENT
      -Wl,--start-group
      TASK_REGISTRY_IPC_WM_O
      ${SRC_FOLDER}/build/lib/libagent_info.so
      ${WAZUHLIB}
      ${WAZUHEXT}
      -Wl,--end-group
      pthread
      dl
      cmocka
      -fprofile-arcs
      -ftest-coverage)
  add_test(NAME test_task_registry_ipc_component COMMAND test_task_registry_ipc_component)
  set_tests_properties(test_task_registry_ipc_component PROPERTIES LABELS "client-agent;agent_info")

  # Component test for the VD feed offset IPC round-trip (issue #38204), same
  # shape as test_task_registry_ipc_component above -- see
  # test_vd_offset_ipc_component.cpp's file banner for what is real vs. harness.
  add_executable(test_vd_offset_ipc_component test_vd_offset_ipc_component.cpp)
  target_include_directories(
      test_vd_offset_ipc_component
      PRIVATE ${SRC_FOLDER}/external/googletest/googletest/include/
              ${SRC_FOLDER}/wazuh_modules/agent_info/include
              ${SRC_FOLDER}/wazuh_modules/src)
  target_link_libraries(
      test_vd_offset_ipc_component
      debug gtestd
      debug gtest_maind
      optimized gtest
      optimized gtest_main
      CLIENT-AGENT
      -Wl,--start-group
      TASK_REGISTRY_IPC_WM_O
      ${SRC_FOLDER}/build/lib/libagent_info.so
      ${WAZUHLIB}
      ${WAZUHEXT}
      -Wl,--end-group
      pthread
      dl
      cmocka
      -fprofile-arcs
      -ftest-coverage)
  add_test(NAME test_vd_offset_ipc_component COMMAND test_vd_offset_ipc_component)
  set_tests_properties(test_vd_offset_ipc_component PROPERTIES LABELS "client-agent;agent_info")
endif()

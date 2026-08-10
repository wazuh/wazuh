# Generate agent upgrade library mingw cross-builds emit .c.obj instead of .c.o,
# so the GLOB has to match both extensions for the agent/manager (Linux .c.o)
# and winagent (mingw .c.obj) flows.
if(${TARGET} STREQUAL "winagent")
  set(_UT_OBJ_EXT ".c.obj")
else()
  set(_UT_OBJ_EXT ".c.o")
endif()
file(
  GLOB_RECURSE
  upgrade_files
  ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*${_UT_OBJ_EXT}
)
list(
  REMOVE_ITEM
  upgrade_files
  ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main${_UT_OBJ_EXT}
)

add_library(UPGRADE_O STATIC ${upgrade_files})

set_source_files_properties(${upgrade_files} PROPERTIES EXTERNAL_OBJECT true
                                                        GENERATED true)

set_target_properties(UPGRADE_O PROPERTIES LINKER_LANGUAGE C)

target_link_libraries(UPGRADE_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate agent upgrade tests
list(APPEND upgrade_names "test_wm_agent_upgrade")
list(
  APPEND
  upgrade_flags
  "-Wl,--wrap,_mtinfo -Wl,--wrap,wm_agent_upgrade_start_agent_module -Wl,--wrap,wm_agent_upgrade_start_manager_module -Wl,--wrap,getpid -Wl,--wrap,unlink -Wl,--wrap,w_query_agentd"
)

if(${TARGET} STREQUAL "manager")

  list(APPEND upgrade_names "test_wm_agent_upgrade_manager")
  list(
    APPEND
    upgrade_flags
    "-Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP \
                            -Wl,--wrap,wm_agent_upgrade_parse_message -Wl,--wrap,wm_agent_upgrade_process_upgrade_command -Wl,--wrap,wm_agent_upgrade_process_upgrade_custom_command \
                            -Wl,--wrap,wm_agent_upgrade_parse_response -Wl,--wrap,sleep -Wl,--wrap,CreateThread \
                            -Wl,--wrap,pthread_exit -Wl,--wrap,getpid -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,so_get_module_handle -Wl,--wrap,so_get_function_sym \
                            -Wl,--wrap,FOREVER -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}"
  )

  list(APPEND upgrade_names "test_wm_agent_upgrade_parsing")
  list(
    APPEND
    upgrade_flags
    "-Wl,--wrap,OS_ReadXML -Wl,--wrap,OS_GetOneContentforElement -Wl,--wrap,OS_ClearXML -Wl,--wrap,w_query_agentd ${DEBUG_OP_WRAPPERS}"
  )

  list(APPEND upgrade_names "test_wm_agent_upgrade_validate")
  list(
    APPEND
    upgrade_flags
    "-Wl,--wrap,wurl_http_get -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,OS_SHA1_File -Wl,--wrap,wurl_request -Wl,--wrap,sleep -Wl,--wrap,wfopen \
                               -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                               -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

  list(APPEND upgrade_names "test_wm_agent_upgrade_commands")
  list(
    APPEND
    upgrade_flags
    "-Wl,--wrap,wm_agent_upgrade_validate_id \
                            -Wl,--wrap,wm_agent_upgrade_validate_system -Wl,--wrap,wm_agent_upgrade_validate_version -Wl,--wrap,wdb_get_agent_info \
                            -Wl,--wrap,wm_agent_upgrade_validate_wpk -Wl,--wrap,wm_agent_upgrade_validate_wpk_version -Wl,--wrap,wm_agent_upgrade_validate_wpk_custom -Wl,--wrap,wm_agent_upgrade_parse_data_response -Wl,--wrap,wm_agent_upgrade_parse_response \
                            -Wl,--wrap,wm_agent_upgrade_send_tasks_information -Wl,--wrap,w_query_agentd -Wl,--wrap,ReadConfig ${DEBUG_OP_WRAPPERS}"
  )

else()

  list(APPEND upgrade_names "test_wm_agent_upgrade_agent")
  list(
    APPEND
    upgrade_flags
    "-Wl,--wrap,wm_sendmsg -Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose -Wl,--wrap,StartMQ -Wl,--wrap,StartMQPredicated -Wl,--wrap,sleep -Wl,--wrap,close -Wl,--wrap,wfopen \
                               -Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,select -Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,wm_agent_upgrade_process_command \
                               -Wl,--wrap,fflush -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,getpid -Wl,--wrap,CreateThread -Wl,--wrap,unlink -Wl,--wrap,fgetpos -Wl,--wrap=fgetc \
                               -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

  list(APPEND upgrade_names "test_wm_agent_upgrade_com")
  list(
    APPEND
    upgrade_flags
    "-Wl,--wrap,w_ref_parent_folder -Wl,--wrap,w_wpk_unsign -Wl,--wrap,unlink -Wl,--wrap,getpid -Wl,--wrap,gzopen \
                               -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove \
                               -Wl,--wrap,gzclose -Wl,--wrap,gzread -Wl,--wrap,mkstemp -Wl,--wrap,atexit -Wl,--wrap,chmod -Wl,--wrap,stat -Wl,--wrap,wfopen \
                               -Wl,--wrap,w_fopen_nofollow \
                               -Wl,--wrap,OS_SHA1_File -Wl,--wrap,getDefine_Int -Wl,--wrap,getDefine_Int_default -Wl,--wrap,cldir_ex -Wl,--wrap,UnmergeFiles -Wl,--wrap,wm_exec -Wl,--wrap,remove \
                               -Wl,--wrap,fgetpos -Wl,--wrap=fgetc  -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}"
  )

endif()

# Compiling tests
list(LENGTH upgrade_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
  list(GET upgrade_names ${counter} test_name)
  list(GET upgrade_flags ${counter} test_flags)

  add_executable(${test_name} ${test_name}.c)

  target_link_libraries(${test_name} ${WAZUHLIB} ${WAZUHEXT} UPGRADE_O
                        ${TEST_DEPS})

  if(${TARGET} STREQUAL "winagent")
    # UPGRADE_O / DEPENDENCIES_O / libwazuh_test bring in objects whose `#ifdef
    # WIN32` paths reference syscheckd symbols that the agent_upgrade tests
    # never exercise. Reuse the existing __wrap_* helpers in
    # src/unit_tests/wrappers/wazuh/syscheckd/ to satisfy the linker — same
    # pattern already used by client-agent/test_buffer on winagent.
    target_link_libraries(
      ${test_name} -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck
      -Wl,--wrap=is_fim_shutdown)
  endif()

  if(NOT test_flags STREQUAL " ")
    target_link_libraries(${test_name} ${test_flags})
  endif()
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

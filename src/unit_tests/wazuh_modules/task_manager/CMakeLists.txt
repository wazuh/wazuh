# Generate task manager library
file(
  GLOB_RECURSE task_files
  ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*.c.o)
list(
  REMOVE_ITEM
  task_files
  ${SRC_FOLDER}/build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main.c.o
)

add_library(TASK_O STATIC ${task_files})

set_source_files_properties(${task_files} PROPERTIES EXTERNAL_OBJECT true
                                                     GENERATED true)

set_target_properties(TASK_O PROPERTIES LINKER_LANGUAGE C)

target_link_libraries(TASK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate task manager tests
list(APPEND task_names "test_wm_task_manager")
list(
  APPEND
  task_flags
  "-Wl,--wrap,pthread_exit -Wl,--wrap,CreateThread -Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,select -Wl,--wrap,close \
                        -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP \
                        -Wl,--wrap,getpid -Wl,--wrap,w_query_agentd -Wl,--wrap,wm_task_cache_init -Wl,--wrap,w_create_thread \
                        -Wl,--wrap,getDefine_Int_default ${DEBUG_OP_WRAPPERS}"
)

list(APPEND task_names "test_wm_task_manager_parsing")
list(APPEND task_flags "-Wl,--wrap,w_get_timestamp ${DEBUG_OP_WRAPPERS}")

list(APPEND task_names "test_wm_task_manager_commands")
list(
  APPEND
  task_flags
  "-Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result -Wl,--wrap,time -Wl,--wrap,wm_sleep_until_interruptible \
                        -Wl,--wrap,wm_task_cache_get -Wl,--wrap,wm_task_cache_set -Wl,--wrap,wm_task_cache_invalidate \
                        -Wl,--wrap,wm_task_manager_generate_task_id \
                        ${DEBUG_OP_WRAPPERS}")

list(APPEND task_names "test_wm_task_manager_tasks")
list(APPEND task_flags "${DEBUG_OP_WRAPPERS}")

# The registry is pure data plus pure functions, so nothing here needs a socket, a thread or a
# database: only the logging wrappers, and getDefine_Int_default for the timeout ordering check.
list(APPEND task_names "test_wm_manager_task_registry")
list(APPEND task_flags "-Wl,--wrap,getDefine_Int_default ${DEBUG_OP_WRAPPERS}")

# Reads /proc for real: the value of a process start time is precisely that it comes from the
# kernel rather than from anything this process could be wrong about, so mocking it would test
# the mock. Only the logging wrappers are needed.
list(APPEND task_names "test_wm_manager_task_owner")
list(APPEND task_flags "${DEBUG_OP_WRAPPERS}")

list(APPEND task_names "test_wm_manager_task_client")
list(APPEND task_flags "-Wl,--wrap,wdbc_query_ex_timeout -Wl,--wrap,wdbc_parse_result -Wl,--wrap,wdbc_close \
                        -Wl,--wrap,time ${DEBUG_OP_WRAPPERS}")

# Compilig tests
list(LENGTH task_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
  list(GET task_names ${counter} test_name)
  list(GET task_flags ${counter} test_flags)

  add_executable(${test_name} ${test_name}.c)

  if(NOT test_flags STREQUAL " ")
    target_link_libraries(${test_name} ${test_flags})
  endif()

  target_link_libraries(${test_name} ${WAZUHLIB} ${WAZUHEXT} TASK_O
                        ${TEST_DEPS})
  add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

# Generate execd library
if(${TARGET} STREQUAL "winagent")
  # On winagent, execd objects are already in DEPENDENCIES_O (winagent.cmake).
  # Creating a separate library from the same objects would cause duplicate globals.
else()
  file(GLOB execd_files
       ${SRC_FOLDER}/build/os_execd/CMakeFiles/execd_lib.dir/src/*.o)
  list(REMOVE_ITEM execd_files ${SRC_FOLDER}/build/os_execd/CMakeFiles/execd_lib.dir/src/main.c.o)

  add_library(EXECD_O STATIC ${execd_files})

  set_source_files_properties(
      ${execd_files}
      PROPERTIES
      EXTERNAL_OBJECT true
      GENERATED true
  )

  set_target_properties(
      EXECD_O
      PROPERTIES
      LINKER_LANGUAGE C
  )

  target_link_libraries(EXECD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)
endif()

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/build/bin)
endif(${TARGET} STREQUAL "winagent")

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Execd is agent-only.
set(EXECD_TEST_ARGV0 "wazuh-execd")

# Generate Execd tests
if(${TARGET} STREQUAL "winagent")
    list(APPEND execd_names "test_win_execd")
    list(APPEND execd_flags "-Wl,--wrap,ReadExecConfig -Wl,--wrap,GetCommandbyName -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,fwrite \
                             -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek \
                             -Wl,--wrap,remove -Wl,--wrap,fgetpos -Wl,--wrap=fgetc -Wl,--wrap,fwrite -Wl,--wrap,wfopen \
                             -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=is_fim_shutdown \
                             -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=fim_db_teardown -Wl,--wrap,w_query_agentd \
                             -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

    list(APPEND execd_names "test_get_command_by_name")
    list(APPEND execd_flags "-Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=is_fim_shutdown \
                             -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=fim_db_teardown -Wl,--wrap,w_query_agentd \
                             ${DEBUG_OP_WRAPPERS}")
else()
    list(APPEND execd_names "test_execd")
    list(APPEND execd_flags "-Wl,--wrap,time -Wl,--wrap,select -Wl,--wrap,OS_RecvUnix -Wl,--wrap,wfopen \
                             -Wl,--wrap,ReadExecConfig -Wl,--wrap,GetCommandbyName -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,fwrite \
                             -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek \
                             -Wl,--wrap,remove -Wl,--wrap,fgetpos -Wl,--wrap=fgetc -Wl,--wrap,fwrite \
                             -Wl,--wrap,fprintf -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

    list(APPEND execd_names "test_get_command_by_name")
    list(APPEND execd_flags "${DEBUG_OP_WRAPPERS}")
endif()

list(LENGTH execd_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET execd_names ${counter} execd_test_name)
    list(GET execd_flags ${counter} execd_test_flags)

    add_executable(${execd_test_name} ${execd_test_name}.c)
    target_compile_definitions(${execd_test_name} PRIVATE ARGV0="${EXECD_TEST_ARGV0}")

    if(${TARGET} STREQUAL "winagent")
        # On winagent, execd objects come from DEPENDENCIES_O (in TEST_DEPS)
        target_link_libraries(
            ${execd_test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            ${TEST_DEPS}
        )
        target_link_libraries(${execd_test_name} fimdb)
    else()
        target_link_libraries(
            ${execd_test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            EXECD_O
            ${TEST_DEPS}
        )
    endif()

    if(NOT execd_test_flags STREQUAL " ")
        target_link_libraries(
            ${execd_test_name}
            ${execd_test_flags}
        )
    endif()
    add_test(NAME ${execd_test_name} COMMAND ${execd_test_name})
endforeach()

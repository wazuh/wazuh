# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Tests list and flags
list(APPEND tests_names "test_wm_github")
set(WM_GITHUB_BASE_FLAGS "-Wl,--wrap,_mwarn -Wl,--wrap,_mdebug1 -Wl,--wrap,_merror -Wl,--wrap,_mtinfo -Wl,--wrap,_mterror\
                          -Wl,--wrap,_mtwarn -Wl,--wrap,_mtdebug1 -Wl,--wrap,_mtdebug2 -Wl,--wrap,StartMQ -Wl,--wrap,sleep \
                          -Wl,--wrap,OS_IsValidIP -Wl,--wrap,OSMatch_Execute -Wl,--wrap,wm_sendmsg -Wl,--wrap,OSRegex_Compile \
                          -Wl,--wrap,wm_state_io -Wl,--wrap,OSRegex_Execute -Wl,--wrap,OSRegex_Execute_ex -Wl,--wrap,OSMatch_Compile \
                          -Wl,--wrap,OSRegex_FreePattern -Wl,--wrap,wurl_http_request -Wl,--wrap,strftime -Wl,--wrap,gmtime_r \
                          -Wl,--wrap,isDebug")
if(${TARGET} STREQUAL "winagent")
    list(APPEND tests_flags "${WM_GITHUB_BASE_FLAGS} -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck -Wl,--wrap=is_fim_shutdown \
                             -Wl,--wrap=fim_db_teardown -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=_imp__rsync_initialize")
else()
    list(APPEND tests_flags "${WM_GITHUB_BASE_FLAGS}")
endif()

list(APPEND use_shared_libs 1)

list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.h")
list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.c")

# Generate wazuh modules library
file(GLOB github ../../../wazuh_modules/*.o)
list(REMOVE_ITEM github ../../../wazuh_modules/main.o)

add_library(GITHUB_O STATIC ${github})

set_source_files_properties(
  ${github}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  GITHUB_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(GITHUB_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Compiling tests
list(LENGTH tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)
    list(GET use_shared_libs ${counter} use_libs)

    if(use_libs EQUAL "1")
      add_executable(${test_name} ${test_name}.c ${shared_libs})
    else ()
      add_executable(${test_name} ${test_name}.c)
    endif()

    if(${TARGET} STREQUAL "server")
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            GITHUB_O
            -lcmocka
            -ldl
            -fprofile-arcs
            -ftest-coverage
        )
    else()
        target_link_libraries(
            ${test_name}
            ${TEST_DEPS}
        )
        if(${TARGET} STREQUAL "winagent")
            target_link_libraries(${test_name} fimdb)
        endif(${TARGET} STREQUAL "winagent")
    endif()


    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

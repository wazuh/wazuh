# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Tests list and flags
list(APPEND tests_names "test_wm_command")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror \
                         -Wl,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_exec,--wrap=StartMQ,--wrap=FOREVER")
list(APPEND use_shared_libs 1)

list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.h")
list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.c")

# Generate wazuh modules library
file(GLOB command ../../../wazuh_modules/*.o)
list(REMOVE_ITEM command ../../../wazuh_modules/main.o)

add_library(COMMAND_O STATIC ${command})

set_source_files_properties(
  ${command}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  COMMAND_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(COMMAND_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


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

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        COMMAND_O
        -lcmocka
        -fprofile-arcs
        -ftest-coverage
    )
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(${test_name} ${test_name})
endforeach()

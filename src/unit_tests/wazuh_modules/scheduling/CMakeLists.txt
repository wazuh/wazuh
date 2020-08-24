# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Tests list and flags
list(APPEND tests_names "test_wmodules_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror")
list(APPEND use_shared_libs 1)

list(APPEND shared_libs "wmodules_scheduling_helpers.h")
list(APPEND shared_libs "wmodules_scheduling_helpers.c")

# Generate modulesd library
file(GLOB modulesd_files ../../../wazuh_modules/*.o)
list(REMOVE_ITEM modulesd_files ../../../wazuh_modules/main.o)
file(GLOB syscollector_files ../../../wazuh_modules/syscollector/*.o)

add_library(MODULESD_O STATIC ${modulesd_files})
add_library(SYSCOLLECTOR_O STATIC ${syscollector_files})

set_source_files_properties(
  ${modulesd_files}
  ${syscollector_files}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  MODULESD_O
  SYSCOLLECTOR_O
  PROPERTIES
  LINKER_LANGUAGE C
)

target_link_libraries(MODULESD_O SYSCOLLECTOR_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


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
        MODULESD_O
        SYSCOLLECTOR_O
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

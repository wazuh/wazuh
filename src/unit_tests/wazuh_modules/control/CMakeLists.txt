# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Tests list and flags
list(APPEND tests_names "test_wm_control")
list(APPEND tests_flags "-Wl,--wrap,sysinfo_networks -Wl,--wrap,sysinfo_free_result ${DEBUG_OP_WRAPPERS}")
list(APPEND use_shared_libs 1)


# Generate wazuh modules library
file(GLOB control ../../../wazuh_modules/*.o)
list(REMOVE_ITEM control ../../../wazuh_modules/main.o)

add_library(CONTROL_O STATIC ${control})

set_source_files_properties(
  ${control}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  CONTROL_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(CONTROL_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


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
            CONTROL_O
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
    endif()


    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

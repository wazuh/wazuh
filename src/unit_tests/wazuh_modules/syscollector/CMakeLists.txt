# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

if(${uname} STREQUAL "Darwin")
  # Tests list and flags
  list(APPEND tests_names "test_syscollector_bsd")
  list(APPEND tests_flags " ")
  list(APPEND use_shared_libs 1)

# Generate modulesd library
file(GLOB syscollector_files
    ${SRC_FOLDER}/wazuh_modules/*.o
    ${SRC_FOLDER}/wazuh_modules/vulnerability_detector/*.o
    ${SRC_FOLDER}/wrapper/macos/libc/*.o)
list(REMOVE_ITEM vulndetector_files ${SRC_FOLDER}/wazuh_modules/main.o)

add_library(SYSCOLLECTOR_O STATIC ${syscollector_files})

set_source_files_properties(
  ${syscollector_files}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  SYSCOLLECTOR_O
  PROPERTIES
  LINKER_LANGUAGE C
)

target_link_libraries(SYSCOLLECTOR_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

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
endif()

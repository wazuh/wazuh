# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Generate wmodules library
file(GLOB wmodules_files
    ${SRC_FOLDER}/wazuh_modules/*.o)
list(REMOVE_ITEM wmodules_files ${SRC_FOLDER}/wazuh_modules/main.o)

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
list(APPEND wmodules_flags " ")

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

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Generate os_regex library
file(GLOB os_regex_files
    ${SRC_FOLDER}/os_regex/*.o)

add_library(OS_REGEX_O STATIC ${os_regex_files})

set_source_files_properties(
    ${os_regex_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_REGEX_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_REGEX_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

if(${TARGET} STREQUAL "winagent")
    link_directories(${SRC_FOLDER}/syscheckd/build/bin)
endif(${TARGET} STREQUAL "winagent")

# Generate os_regex tests
list(APPEND os_regex_names "test_os_regex")
if(${TARGET} STREQUAL "winagent")
list(APPEND os_regex_flags "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig \
                            -Wl,--wrap,getSyscheckInternalOptions -Wl,--wrap=Start_win32_Syscheck \
                            -Wl,--wrap,syscom_dispatch -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                            -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND os_regex_flags " ")
endif()

list(APPEND os_regex_def " ")

# Generate os_regex_match tests
list(APPEND os_regex_names "test_os_regex_match")
list(APPEND os_regex_flags " ")
list(APPEND os_regex_def " ")

# OS_Regex execute, regex_matching
list(APPEND os_regex_names "test_os_regex_execute")
if(${TARGET} STREQUAL "winagent")
list(APPEND os_regex_flags "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig \
                            -Wl,--wrap,getSyscheckInternalOptions -Wl,--wrap=Start_win32_Syscheck \
                            -Wl,--wrap,syscom_dispatch -Wl,--wrap=is_fim_shutdown -Wl,--wrap=_imp__dbsync_initialize \
                            -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown")
else()
list(APPEND os_regex_flags " ")
endif()
set(JSON_PATH_TEST "${CMAKE_CURRENT_SOURCE_DIR}/test_os_regex_execute.json")
list(APPEND os_regex_def "JSON_PATH_TEST=\"${JSON_PATH_TEST}\"")

# Compiling tests
list(LENGTH os_regex_names count)
math(EXPR count "${count} - 1")

foreach(counter RANGE ${count})
    list(GET os_regex_names ${counter} test_name)
    list(GET os_regex_flags ${counter} test_flags)
    list(GET os_regex_def ${counter} test_macro)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_REGEX_O
        ${TEST_DEPS}
    )
    if(${TARGET} STREQUAL "winagent")
          target_link_libraries(${test_name} fimdb)
    endif(${TARGET} STREQUAL "winagent")

    if(NOT test_macro STREQUAL " ")
    target_compile_definitions(
        ${test_name} PRIVATE
        ${test_macro}
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

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

list(APPEND md5_sha1_tests_names "test_md5_sha1_sha256_op")
list(APPEND md5_sha1_tests_flags "-Wl,--wrap,_mwarn -Wl,--wrap,wpopenv,--wrap,wpclose,--wrap,fread,--wrap,fclose,--wrap,fflush,--wrap,fgets,--wrap,fgetpos \
                                  -Wl,--wrap,fseek,--wrap,fwrite,--wrap,remove,--wrap,fgetc,--wrap,fopen,--wrap,wfopen -Wl,--wrap,popen")

# Compiling tests
list(LENGTH md5_sha1_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET md5_sha1_tests_names ${counter} test_name)
    list(GET md5_sha1_tests_flags ${counter} test_flags)
    add_executable(${test_name} ${test_name}.c)
    if(${TARGET} STREQUAL "server")
        target_link_libraries(
            ${test_name}
            ${TEST_DEPS}
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

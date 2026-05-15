# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

list(APPEND os_crypto_sha1_tests_names "test_sha1_op")
# On winagent OS_SHA1_File_Nbytes uses w_fopen_r (3-arg variant) instead of
# wfopen; the test selects the wrapper via #ifdef TEST_WINAGENT so the wrap
# flag must be present at link time on that target. Build the flag string in
# pieces and string-concatenate so an empty extra block doesn't leave trailing
# whitespace (CMP0004 hard error).
set(_sha1_base_flags "-Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fread \
-Wl,--wrap,fseek -Wl,--wrap,fwrite -Wl,--wrap,remove -Wl,--wrap,fprintf \
-Wl,--wrap,fgets -Wl,--wrap,fgetpos -Wl,--wrap,fgetc -Wl,--wrap,wfopen -Wl,--wrap,popen")
if(${TARGET} STREQUAL "winagent")
    set(_sha1_base_flags "${_sha1_base_flags} -Wl,--wrap=w_fopen_r")
endif()
list(APPEND os_crypto_sha1_tests_flags "${_sha1_base_flags}")

# Compiling tests
list(LENGTH os_crypto_sha1_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_crypto_sha1_tests_names ${counter} test_name)
    list(GET os_crypto_sha1_tests_flags ${counter} test_flags)
    add_executable(${test_name} ${test_name}.c)
    if(${TARGET} STREQUAL "manager")
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

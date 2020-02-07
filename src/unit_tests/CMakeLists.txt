# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

# set(TARGET winagent)
# set(CMAKE_VERBOSE_MAKEFILE ON)

# message("${TARGET}")

set(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../)

include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER})

# Wazuh libraries
find_library(WAZUHLIB NAMES libwazuh.a HINTS "${SRC_FOLDER}")
if(NOT WAZUHLIB)
  message(FATAL_ERROR "libwazuh.a not found! Aborting...")
endif()

# Enable testing
enable_testing()

# Add target specific file
if(NOT TARGET)
  message(FATAL_ERROR "No TARGET specified. Aborting...")
elseif(${TARGET} STREQUAL "server")
  include("./server.cmake")
elseif(${TARGET} STREQUAL "agent")
  include("./agent.cmake")
elseif(${TARGET} STREQUAL "winagent")
  include("./winagent.cmake")
else()
  message(FATAL_ERROR "Invalid TARGET '${TARGET}'. Aborting...")
endif()

if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

add_subdirectory(syscheckd)

# Tests list and flags
list(APPEND tests_names "test_file_op")
list(APPEND tests_flags "-Wl,--wrap,isChroot -Wl,--wrap,mferror -Wl,--wrap,stat -Wl,--wrap,chmod -Wl,--wrap,File_DateofChange -Wl,--wrap,getpid -Wl,--wrap,unlink -Wl,--wrap,_merror -Wl,--wrap,_minfo -Wl,--wrap,_mwarn -Wl,--wrap,fopen")

list(APPEND tests_names "test_integrity_op")
list(APPEND tests_flags " ")

list(APPEND tests_names "test_rbtree_op")
list(APPEND tests_flags " ")


list(APPEND tests_names "test_wdb_integrity")
list(APPEND tests_flags "-Wl,--wrap,_mdebug1 -Wl,--wrap,wdb_stmt_cache -Wl,--wrap,sqlite3_step -Wl,--wrap,sqlite3_errmsg \
                         -Wl,--wrap,EVP_DigestInit_ex -Wl,--wrap,EVP_DigestUpdate -Wl,--wrap,_DigestFinal_ex \
                         -Wl,--wrap,sqlite3_column_text -Wl,--wrap,_mdebug2")

list(APPEND tests_names "test_version_op")
list(APPEND tests_flags "-Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose")

list(APPEND tests_names "test_syscheck_op")
list(APPEND tests_flags "-Wl,--wrap,rmdir_ex -Wl,--wrap,wreaddir -Wl,--wrap,_mdebug1 -Wl,--wrap,_mdebug2 \
                        -Wl,--wrap,_mwarn -Wl,--wrap,_merror -Wl,--wrap,getpwuid_r -Wl,--wrap,getgrgid \
                         -Wl,--wrap,cJSON_CreateArray -Wl,--wrap,cJSON_CreateObject -Wl,--wrap,wstr_split \
                         -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_SendSecureTCP")

# Config files
configure_file("test_syscheck.conf" "syscheckd/test_syscheck.conf" COPYONLY)
configure_file("test_internal_options.conf" "syscheckd/internal_options.conf" COPYONLY)

# Compiling tests
list(LENGTH tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(${test_name} ${test_name})
endforeach()


# Coverage
find_program(LCOV_PATH lcov)
if(NOT LCOV_PATH)
  message(FATAL_ERROR "lcov not found! Aborting...")
endif()

find_program(GCOV_PATH gcov)
if(NOT GCOV_PATH)
  message(FATAL_ERROR "gcov not found! Aborting...")
endif()

find_program(GENHTML_PATH genhtml)
if(NOT GENHTML_PATH)
  message(FATAL_ERROR "genhtml not found! Aborting...")
endif()

add_custom_target(coverage
    # Cleanup lcov
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} -directory ${SRC_FOLDER} --rc lcov_branch_coverage=1 --zerocounters

    # Create baseline to make sure untouched files show up in the report
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -c -i -d ${SRC_FOLDER} --rc lcov_branch_coverage=1 -o coverage.base

    # Run tests
    COMMAND ctest

    # Capturing lcov counters and generating report
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} --directory ${SRC_FOLDER} --capture --rc lcov_branch_coverage=1 --output-file coverage.info

    # Add baseline counters
    COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -a coverage.base -a coverage.info --rc lcov_branch_coverage=1 --output-file coverage.total
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} --remove coverage.total "*external/*" --rc lcov_branch_coverage=1 --output-file coverage.info.cleaned

    # Generate HTML report
    COMMAND ${GENHTML_PATH} -q --output-directory coverage-report --title "WAZUH unit-tests coverage" --rc lcov_branch_coverage=1 --legend coverage.info.cleaned

    # Clean counters
    COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total coverage.info.cleaned
)

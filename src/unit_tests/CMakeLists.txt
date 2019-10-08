# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.13)

INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/../headers)
INCLUDE_DIRECTORIES(${CMAKE_SOURCE_DIR}/../)

FIND_LIBRARY(WAZUHLIB NAMES libwazuh.a HINTS "${CMAKE_SOURCE_DIR}/../")
FIND_LIBRARY(WAZUHEXT NAMES libwazuhext.so HINTS "${CMAKE_SOURCE_DIR}/../")


ADD_COMPILE_OPTIONS(-ggdb)


# Generate syscheck library
FILE(GLOB sysfiles ../syscheckd/*.o)
LIST(REMOVE_ITEM sysfiles ../syscheckd/main.o)
FILE(GLOB rootfiles ../rootcheck/*.o)

ADD_LIBRARY(SYSCHECK_O STATIC ${sysfiles})
ADD_LIBRARY(ROOTCHECK_O STATIC ${rootfiles})

SET_SOURCE_FILES_PROPERTIES(
  ${sysfiles}
  ${rootfiles}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

SET_TARGET_PROPERTIES(
  SYSCHECK_O
  ROOTCHECK_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

TARGET_LINK_LIBRARIES(SYSCHECK_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


# Tests list and flags
LIST(APPEND tests_names "test_file_op")
LIST(APPEND tests_flags "-Wl,--wrap,isChroot -Wl,--wrap,chmod -Wl,--wrap,File_DateofChange -Wl,--wrap,getpid -Wl,--wrap,unlink")

LIST(APPEND tests_names "test_integrity_op")
LIST(APPEND tests_flags " ")

LIST(APPEND tests_names "test_rbtree_op")
LIST(APPEND tests_flags " ")

LIST(APPEND tests_names "test_version_op")
LIST(APPEND tests_flags "-Wl,--wrap,fopen -Wl,--wrap,fgets -Wl,--wrap,fclose")

LIST(APPEND tests_names "test_create_db")
LIST(APPEND tests_flags " ")


# Declare all tests targets
LIST(LENGTH tests_names count)
MATH(EXPR count "${count} - 1")
FOREACH(i RANGE ${count})
    LIST(GET tests_names ${i} test_name)
    LIST(GET tests_flags ${i} test_flags)

    ADD_EXECUTABLE(${test_name} ${test_name}.c)

    TARGET_LINK_LIBRARIES(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        SYSCHECK_O
        -lcmocka
        -fprofile-arcs
        -ftest-coverage
    )
    IF(test_flags STREQUAL " ")
    ELSE()
        TARGET_LINK_LIBRARIES(
            ${test_name}
            ${test_flags}
        )
    ENDIF()
    ADD_TEST(${test_name} ${test_name})
ENDFOREACH()

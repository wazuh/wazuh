# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

set(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../)

include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER})


# Wazuh libraries
find_library(WAZUHLIB NAMES libwazuh.a HINTS "${SRC_FOLDER}")
if(NOT WAZUHLIB)
  message(FATAL_ERROR "libwazuh.a not found! Aborting...")
endif()

find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")
if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext.so not found! Aborting...")
endif()


# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage)


# Enable testing
enable_testing()


# Tests list and flags
list(APPEND tests_names "test_wm_gcp")
list(APPEND tests_flags "-Wl,--wrap,wm_exec,--wrap,_mtdebug1,--wrap,_mtinfo,--wrap,_mtwarn,--wrap,_mterror \
                         -Wl,--wrap,sched_scan_dump,--wrap,sched_scan_get_time_until_next_scan,--wrap,cJSON_CreateObject \
                         -Wl,--wrap,FOREVER,--wrap,_mtdebug2")

list(APPEND tests_names "test_wmodules_gcp")
list(APPEND tests_flags "-Wl,--wrap,sched_scan_read,--wrap,realpath,--wrap,IsFile,--wrap,_mwarn,--wrap,_merror")


# Generate wazuh modules library
file(GLOB gcp ../../../wazuh_modules/*.o ../../../config/*.o)
list(REMOVE_ITEM gcp ../../../wazuh_modules/main.o)

add_library(GCP_O STATIC ${gcp})

set_source_files_properties(
  ${gcp}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  GCP_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(GCP_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


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
        GCP_O
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

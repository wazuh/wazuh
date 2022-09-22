# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.5.1)

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
add_compile_options(-ggdb -O0 -g -coverage -DENABLE_SYSC)


# Enable testing
enable_testing()


# Tests list and flags
list(APPEND tests_names "test_wmodules_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_aws_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_aws_run_s3,--wrap=StartMQ,--wrap=FOREVER")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_azure_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_exec,--wrap=StartMQ,--wrap=FOREVER,--wrap=SendMSG")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_ciscat_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=os_random,--wrap=StartMQ,--wrap=FOREVER,--wrap=IsDir")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_command_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_exec,--wrap=StartMQ,--wrap=FOREVER")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_docker_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=FOREVER,--wrap=wpclose,--wrap=fgets,--wrap=wpopenl")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_gcp_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=FOREVER,--wrap=realpath,--wrap=IsFile")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_oscap_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=wm_exec,--wrap=StartMQ,--wrap=FOREVER,--wrap=wm_sendmsg,--wrap=SendMSG")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_sca_scheduling")
list(APPEND tests_flags "-Wl,--wrap=time,--wrap=w_time_delay,--wrap=w_sleep_until,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=FOREVER,--wrap=IsFile,--wrap=getDefine_Int,--wrap=StartMQ,--wrap=CreateThread,--wrap=wm_exec,--wrap=wm_sendmsg")
list(APPEND use_shared_libs 1)

list(APPEND tests_names "test_schedule_scan")
list(APPEND tests_flags "-Wl,--wrap=OS_StrIsNum,--wrap=_merror,--wrap=w_time_delay,--wrap=time,--wrap=_mwarn")
list(APPEND use_shared_libs 0)

list(APPEND shared_libs "global_helpers.c")
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

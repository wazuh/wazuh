# Copyright (C) 2015-2019, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

set(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../)

include_directories(${SRC_FOLDER}/headers)
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
list(APPEND tests_names "test_run_rc_sys")
list(APPEND tests_flags "-Wl,--wrap,lstat -Wl,--wrap,notify_rk -Wl,--wrap,open -Wl,--wrap,read -Wl,--wrap,strcmp -Wl,--wrap,IsNFS -Wl,--wrap,opendir -Wl,--wrap,readdir -Wl,--wrap,skipFS -Wl,--wrap,closedir")


# Generate syscheck library
file(GLOB sysfiles ../syscheckd/*.o)
list(REMOVE_ITEM sysfiles ../syscheckd/main.o)
file(GLOB rootfiles ../rootcheck/*.o)

add_library(SYSCHECK_O STATIC ${sysfiles})
add_library(ROOTCHECK_O STATIC ${rootfiles})

set_source_files_properties(
  ${sysfiles}
  ${rootfiles}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  SYSCHECK_O
  ROOTCHECK_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(SYSCHECK_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


# Generate analysisd library
file(GLOB analysisd_files
  ../analysisd/*.o
  ../analysisd/cdb/*.o
  ../analysisd/decoders/*.o
  ../analysisd/decoders/plugins/*.o)

add_library(ANALYSISD_O STATIC ${analysisd_files})

set_source_files_properties(
  ${analysisd_files}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  ANALYSISD_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(ANALYSISD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)


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
        SYSCHECK_O
        ANALYSISD_O
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

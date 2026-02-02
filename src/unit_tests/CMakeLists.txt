# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.
cmake_minimum_required(VERSION 3.10)

PROJECT(UnitTests C)

set(CMAKE_C_STANDARD 11)
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

message(Source folder: ${SRC_FOLDER})
include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/config/include)
include_directories(${SRC_FOLDER}/os_crypto/md5)
include_directories(${SRC_FOLDER}/os_crypto/sha1)
include_directories(${SRC_FOLDER}/os_crypto/sha256)
include_directories(${SRC_FOLDER}/os_crypto/md5_sha1_sha256)
include_directories(${SRC_FOLDER}/os_net)
include_directories(${SRC_FOLDER}/os_regex)
include_directories(${SRC_FOLDER}/os_xml)
include_directories(${SRC_FOLDER}/shared_modules)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/audit-userspace/lib)
include_directories(${SRC_FOLDER}/external/bzip2)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/msgpack/include)
include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/router/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include/)
include_directories(${SRC_FOLDER}/wazuh_modules/include/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/task_manager/)
add_definitions(-DWAZUH_UNIT_TESTING)

# Find libwazuh
find_library(WAZUHLIB_WAZUH NAMES wazuh libwazuh.a HINTS "${SRC_FOLDER}")
if(NOT WAZUHLIB_WAZUH)
  message(FATAL_ERROR "libwazuh.a not found in ${SRC_FOLDER}. Aborting...")
endif()

# Find libconfig
find_library(WAZUHLIB_CONFIG NAMES config libconfig.a HINTS "${SRC_FOLDER}/build/lib")
if(NOT WAZUHLIB_CONFIG)
  message(FATAL_ERROR "libconfig.a not found in ${SRC_FOLDER}. Aborting...")
endif()

# Find libwazuh_modules
find_library(WAZUHLIB_WM NAMES wazuh_modulesd_lib libwazuh_modulesd_lib.a HINTS "${SRC_FOLDER}/build/lib")
if(NOT WAZUHLIB_WM)
  message(FATAL_ERROR "libwazuh_modulesd_lib.a not found in ${SRC_FOLDER}. Aborting...")
endif()

# Store both in WAZUHLIB (list)
set(WAZUHLIB
  ${WAZUHLIB_CONFIG}
  ${WAZUHLIB_WAZUH}
  ${WAZUHLIB_WM}
)

# Enable testing
enable_testing()

# Add target specific file
if(NOT TARGET)
  message(FATAL_ERROR "No TARGET specified. Aborting...")
elseif(${TARGET} STREQUAL "server")
  include("./server.cmake")
  configure_file("config_files/test_global.conf" "wazuh_modules/vulnerability_detection/test_global.conf" COPYONLY)
  configure_file("config_files/test_vulnerability_detection_multiple_configuration.conf" "wazuh_modules/vulnerability_detection/test_vulnerability_detection_multiple_configuration.conf" COPYONLY)
  configure_file("config_files/test_vulnerability_detection_duplicate_configuration.conf" "wazuh_modules/vulnerability_detection/test_vulnerability_detection_duplicate_configuration.conf" COPYONLY)
  configure_file("config_files/test_vulnerability_detection.conf" "wazuh_modules/vulnerability_detection/test_vulnerability_detection.conf" COPYONLY)
  configure_file("config_files/test_vulnerability_detection_invalid_index_status_setting.conf" "wazuh_modules/vulnerability_detection/test_vulnerability_detection_invalid_index_status_setting.conf" COPYONLY)
  configure_file("config_files/test_global_no_cti_url.conf" "wazuh_modules/vulnerability_detection/test_global_no_cti_url.conf" COPYONLY)
elseif(${TARGET} STREQUAL "agent")
  include("./agent.cmake")
  configure_file("config_files/test_anti_tampering.conf" "client-agent/test_anti_tampering.conf" COPYONLY)
  configure_file("config_files/test_anti_tampering_no.conf" "client-agent/test_anti_tampering_no.conf" COPYONLY)
  configure_file("config_files/test_anti_tampering_invalid.conf" "client-agent/test_anti_tampering_invalid.conf" COPYONLY)
elseif(${TARGET} STREQUAL "winagent")
  include("./winagent.cmake")
else()
  message(FATAL_ERROR "Invalid TARGET '${TARGET}'. Aborting...")
endif()

if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

if((${uname} STREQUAL "Linux") OR (${uname} STREQUAL "Win32"))
  add_subdirectory(syscheckd)
  add_subdirectory(shared)
  add_subdirectory(os_xml)
  add_subdirectory(os_regex)
  add_subdirectory(os_zlib)
  add_subdirectory(config)
  endif()

if(${uname} STREQUAL "Linux")
  add_subdirectory(os_net)
  add_subdirectory(active-response)
  endif()

# Config files
if(${TARGET} STREQUAL "winagent")
  configure_file("config_files/test_syscheck_win.conf" "syscheckd/test_syscheck.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win2.conf" "syscheckd/test_syscheck2.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win3.conf" "syscheckd/test_syscheck3.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win4.conf" "syscheckd/test_syscheck4.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win.conf" "syscheckd/ossec.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win_max_dir.conf" "syscheckd/test_syscheck_max_dir.conf" COPYONLY)
  configure_file("config_files/test_empty_config.conf" "syscheckd/test_empty_config.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_internal_options.conf" "syscheckd/internal_options.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_local_internal_options.conf" "syscheckd/local_internal_options.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_top_level_win.conf" "syscheckd/test_syscheck_top_level.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_config_win.conf" "syscheckd/test_syscheck_config.conf" NEWLINE_STYLE WIN32)
else()
  configure_file("config_files/test_syscheck.conf" "syscheckd/test_syscheck.conf" COPYONLY)
  configure_file("config_files/test_syscheck_max_dir.conf" "syscheckd/test_syscheck_max_dir.conf" COPYONLY)
  configure_file("config_files/test_syscheck2.conf" "syscheckd/test_syscheck2.conf" COPYONLY)
  configure_file("config_files/test_syscheck3.conf" "syscheckd/test_syscheck3.conf" COPYONLY)
  configure_file("config_files/test_syscheck4.conf" "syscheckd/test_syscheck4.conf" COPYONLY)
  configure_file("config_files/test_empty_config.conf" "syscheckd/test_empty_config.conf" COPYONLY)
  configure_file("config_files/test_internal_options.conf" "syscheckd/internal_options.conf" COPYONLY)
  configure_file("config_files/test_local_internal_options.conf" "syscheckd/local_internal_options.conf" COPYONLY)
  configure_file("config_files/test_syscheck_top_level.conf" "syscheckd/test_syscheck_top_level.conf" COPYONLY)
  configure_file("config_files/test_syscheck.conf" "syscheckd/test_syscheck_config.conf" COPYONLY)
endif()

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
    COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} --remove coverage.total "*external/*" --remove coverage.total "*unit_tests/*" --remove coverage.total "*data_provider/*" --remove coverage.total "*shared_modules/*" --remove coverage.total "*syscollector/*" --remove coverage.total "*syscheckd/src/db/*" --rc lcov_branch_coverage=1 --output-file coverage.info.cleaned

    # Generate HTML report
    COMMAND ${GENHTML_PATH} -q --output-directory coverage-report --title "WAZUH unit-tests coverage" --rc lcov_branch_coverage=1 --legend coverage.info.cleaned

    # Clean counters
    COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total coverage.info.cleaned
)

# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License (version 2) as published by the
# FSF - Free Software Foundation.
cmake_minimum_required(VERSION 3.10)

project(UnitTests C)

set(CMAKE_C_STANDARD 11)
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)

message(Source folder: ${SRC_FOLDER})
include_directories(${SRC_FOLDER}/shared/include)
include_directories(${SRC_FOLDER}/active-response/include)
include_directories(${SRC_FOLDER}/config/include)
include_directories(${SRC_FOLDER}/client-agent/include/)
include_directories(${SRC_FOLDER}/client-agent/src/)
include_directories(${SRC_FOLDER}/logcollector/include/)
include_directories(${SRC_FOLDER}/os_execd/include/)
include_directories(${SRC_FOLDER}/syscheckd/include/)
include_directories(${SRC_FOLDER}/data_provider/include/)
include_directories(${SRC_FOLDER}/shared/include/error_messages)
include_directories(${SRC_FOLDER}/shared/os_crypto/aes)
include_directories(${SRC_FOLDER}/shared/os_crypto/blowfish)
include_directories(${SRC_FOLDER}/shared/os_crypto/hmac)
include_directories(${SRC_FOLDER}/shared/os_crypto/md5)
include_directories(${SRC_FOLDER}/shared/os_crypto/sha1)
include_directories(${SRC_FOLDER}/shared/os_crypto/sha256)
include_directories(${SRC_FOLDER}/shared/os_crypto/sha512)
include_directories(${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256)
include_directories(${SRC_FOLDER}/shared/os_net)
include_directories(${SRC_FOLDER}/shared/os_regex)
include_directories(${SRC_FOLDER}/shared/os_xml)
include_directories(${SRC_FOLDER}/shared/os_zlib)
include_directories(${SRC_FOLDER}/external/curl/include/curl/)
include_directories(${SRC_FOLDER}/external/libpcre2/include/)
include_directories(${SRC_FOLDER}/external/libyaml/include)
include_directories(${SRC_FOLDER}/external/libplist/bin/include/)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/audit-userspace/lib)
include_directories(${SRC_FOLDER}/external/bzip2)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/shared_modules)
include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/router/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/wazuh_modules/include/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager/)
include_directories(${SRC_FOLDER}/wazuh_modules/src/task_manager/)
include_directories(${SRC_FOLDER}/wazuh_db/include/)
add_definitions(-DWAZUH_UNIT_TESTING)

# Find libwazuh_test (contains test wrappers for unit testing)
find_library(
  WAZUHLIB_WAZUH
  NAMES wazuh_test libwazuh_test.a
  HINTS "${SRC_FOLDER}/build/lib")
if(NOT WAZUHLIB_WAZUH)
  message(
    FATAL_ERROR
      "libwazuh_test.a not found in ${SRC_FOLDER}/build/lib. Aborting...")
endif()

# Find libconfig
find_library(
  WAZUHLIB_CONFIG
  NAMES config libconfig.a
  HINTS "${SRC_FOLDER}/build/lib")
if(NOT WAZUHLIB_CONFIG)
  message(FATAL_ERROR "libconfig.a not found in ${SRC_FOLDER}. Aborting...")
endif()

# Find libwazuh_modules
find_library(
  WAZUHLIB_WM
  NAMES wazuh_modulesd_lib libwazuh_modulesd_lib.a
  HINTS "${SRC_FOLDER}/build/lib")
if(NOT WAZUHLIB_WM)
  message(
    FATAL_ERROR
      "libwazuh_modulesd_lib.a not found in ${SRC_FOLDER}. Aborting...")
endif()

# Store both in WAZUHLIB (list)
set(WAZUHLIB ${WAZUHLIB_CONFIG} ${WAZUHLIB_WAZUH} ${WAZUHLIB_WM})

# Enable testing
enable_testing()

# Add target specific file
if(NOT TARGET)
  message(FATAL_ERROR "No TARGET specified. Aborting...")
elseif(${TARGET} STREQUAL "manager")
  include("./server.cmake")
  configure_file(
    "config_files/test_vulnerability_detection_multiple_configuration.conf"
    "wazuh_modules/vulnerability_detection/test_vulnerability_detection_multiple_configuration.conf"
    COPYONLY)
  configure_file(
    "config_files/test_vulnerability_detection_duplicate_configuration.conf"
    "wazuh_modules/vulnerability_detection/test_vulnerability_detection_duplicate_configuration.conf"
    COPYONLY)
  configure_file(
    "config_files/test_vulnerability_detection.conf"
    "wazuh_modules/vulnerability_detection/test_vulnerability_detection.conf"
    COPYONLY)
  configure_file(
    "config_files/test_vulnerability_detection_invalid_index_status_setting.conf"
    "wazuh_modules/vulnerability_detection/test_vulnerability_detection_invalid_index_status_setting.conf"
    COPYONLY)
elseif(${TARGET} STREQUAL "agent")
  include("./agent.cmake")
  configure_file("config_files/test_anti_tampering.conf"
                 "client-agent/test_anti_tampering.conf" COPYONLY)
  configure_file("config_files/test_anti_tampering_no.conf"
                 "client-agent/test_anti_tampering_no.conf" COPYONLY)
  configure_file("config_files/test_anti_tampering_invalid.conf"
                 "client-agent/test_anti_tampering_invalid.conf" COPYONLY)
elseif(${TARGET} STREQUAL "winagent")
  include("./winagent.cmake")
else()
  message(FATAL_ERROR "Invalid TARGET '${TARGET}'. Aborting...")
endif()

if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

if((CMAKE_SYSTEM_NAME STREQUAL "Linux") OR (CMAKE_SYSTEM_NAME STREQUAL "Windows"
                                           ))
  if(NOT ${TARGET} STREQUAL "manager")
    add_subdirectory(syscheckd)
  endif()
  add_subdirectory(shared)
  add_subdirectory(os_xml)
  add_subdirectory(os_regex)
  add_subdirectory(os_zlib)
  add_subdirectory(config)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_subdirectory(os_net)
  if(NOT ${TARGET} STREQUAL "manager")
    add_subdirectory(active-response)
  endif()
endif()

# Config files
if(${TARGET} STREQUAL "winagent")
  configure_file("config_files/test_syscheck_win.conf"
                 "syscheckd/test_syscheck.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win2.conf"
                 "syscheckd/test_syscheck2.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win3.conf"
                 "syscheckd/test_syscheck3.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win4.conf"
                 "syscheckd/test_syscheck4.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win.conf" "syscheckd/ossec.conf"
                 NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_win_max_dir.conf"
                 "syscheckd/test_syscheck_max_dir.conf" COPYONLY)
  configure_file("config_files/test_empty_config.conf"
                 "syscheckd/test_empty_config.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_internal_options.conf"
                 "syscheckd/internal_options.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_local_internal_options.conf"
                 "syscheckd/local_internal_options.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_top_level_win.conf"
                 "syscheckd/test_syscheck_top_level.conf" NEWLINE_STYLE WIN32)
  configure_file("config_files/test_syscheck_config_win.conf"
                 "syscheckd/test_syscheck_config.conf" NEWLINE_STYLE WIN32)
else()
  configure_file("config_files/test_syscheck.conf"
                 "syscheckd/test_syscheck.conf" COPYONLY)
  configure_file("config_files/test_syscheck_max_dir.conf"
                 "syscheckd/test_syscheck_max_dir.conf" COPYONLY)
  configure_file("config_files/test_syscheck2.conf"
                 "syscheckd/test_syscheck2.conf" COPYONLY)
  configure_file("config_files/test_syscheck3.conf"
                 "syscheckd/test_syscheck3.conf" COPYONLY)
  configure_file("config_files/test_syscheck4.conf"
                 "syscheckd/test_syscheck4.conf" COPYONLY)
  configure_file("config_files/test_empty_config.conf"
                 "syscheckd/test_empty_config.conf" COPYONLY)
  configure_file("config_files/test_internal_options.conf"
                 "syscheckd/internal_options.conf" COPYONLY)
  configure_file("config_files/test_local_internal_options.conf"
                 "syscheckd/local_internal_options.conf" COPYONLY)
  configure_file("config_files/test_syscheck_top_level.conf"
                 "syscheckd/test_syscheck_top_level.conf" COPYONLY)
  configure_file("config_files/test_syscheck.conf"
                 "syscheckd/test_syscheck_config.conf" COPYONLY)
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

# Target-specific extra exclusions for the lcov --remove pass.
# These paths exist in the source tree of every target but only matter to the
# manager/server flow, so we drop them only from the agent report. The manager
# report keeps measuring them as before.
#   - wazuh_modules/src/wm_database.c: server-only module bridge. Has a cmocka
#     test in manager (test_wm_database) so it stays in the manager report.
#   - config/src/{authd-config,remote-config,wazuh_db-config}.c: server-only config
#     parsers. Compiled in the agent binary because they are not in config/CMakeLists.txt
#     REMOVE_ITEM list, but never exercised because the corresponding subsystems
#     (authd, remoted, wazuh-db) are not part of the agent runtime. Manager has
#     cmocka tests for all three (test_authd-config, test_remote-config,
#     test_wazuh_db-config).
#   - shared/os_crypto/shared/: msgs.c has #ifdef CLIENT branches that diverge from
#     the manager flow the tests were written against; tests stay manager-only.
set(TARGET_LCOV_EXTRA_REMOVE)
if(${TARGET} STREQUAL "agent")
  list(APPEND TARGET_LCOV_EXTRA_REMOVE
       --remove coverage.total "*wazuh_modules/src/wm_database.c"
       --remove coverage.total "*config/src/authd-config.c"
       --remove coverage.total "*config/src/remote-config.c"
       --remove coverage.total "*config/src/wazuh_db-config.c"
       --remove coverage.total "*shared/os_crypto/shared/*")
endif()

add_custom_target(
  coverage
  # Cleanup lcov
  COMMAND ${LCOV_PATH} --gcov-tool ${GCOV_PATH} -directory ${SRC_FOLDER} --rc
          branch_coverage=1 --ignore-errors mismatch,mismatch --zerocounters
  # Create baseline to make sure untouched files show up in the report
  COMMAND ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -c -i -d ${SRC_FOLDER} --rc
          branch_coverage=1 --ignore-errors mismatch,mismatch -o coverage.base
  # Run tests
  COMMAND ctest
  # Capturing lcov counters and generating report
  COMMAND
    ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} --directory ${SRC_FOLDER} --capture
    --rc branch_coverage=1 --ignore-errors mismatch,mismatch --output-file
    coverage.info
  # Add baseline counters
  COMMAND
    ${LCOV_PATH} -q --gcov-tool ${GCOV_PATH} -a coverage.base -a coverage.info
    --rc branch_coverage=1 --ignore-errors mismatch,mismatch --output-file
    coverage.total
  # Globally excluded paths (apply to every target):
  #   - external/, unit_tests/, data_provider/, shared_modules/, syscollector/,
  #     syscheckd/src/db/, syscheckd/src/ebpf/: out of scope for legacy UT coverage.
  #   - */include/c++/*  /usr/include/*  *usr/share/mingw-w64/*: libstdc++,
  #     glibc and mingw-w64 system headers (template instantiations and inline
  #     definitions inflate the function/branch denominator without representing
  #     project code).
  #   - engine/: wazuh-engine has its own coverage workflow (5_testunit_engine.yml);
  #     legacy UT cmocka does not exercise any of its sources.
  #   - wazuh_modules/{agent_info,sca,vulnerability_scanner,router,inventory_sync,
  #     content_manager,indexer_connector}/: C++ modules with their own coverage
  #     workflow (5_testunit_<module>.yml + coverage_cpp action); legacy UT cmocka
  #     does not exercise them in any target.
  #   - wazuh_modules/src/wm_{router,content_manager,inventory_sync,
  #     vulnerability_scanner}.c: C bridge files for the above C++ modules. Their
  #     wm_*_read() entry points are registered only under #ifndef CLIENT, but no
  #     cmocka test exercises them in either target — the logic is covered by each
  #     module's dedicated workflow.
  # Target-specific exclusions live in TARGET_LCOV_EXTRA_REMOVE (set above).
  COMMAND
    ${LCOV_PATH} --gcov-tool ${GCOV_PATH} --remove coverage.total "*external/*"
    --remove coverage.total "*unit_tests/*" --remove coverage.total
    "*data_provider/*" --remove coverage.total "*shared_modules/*" --remove
    coverage.total "*syscollector/*" --remove coverage.total
    "*syscheckd/src/db/*" --remove coverage.total "*syscheckd/src/ebpf/*"
    --remove coverage.total "*/include/c++/*" --remove coverage.total
    "/usr/include/*" --remove coverage.total "*usr/share/mingw-w64/*"
    --remove coverage.total "*engine/*"
    --remove coverage.total "*wazuh_modules/agent_info/*" --remove coverage.total
    "*wazuh_modules/sca/*" --remove coverage.total
    "*wazuh_modules/vulnerability_scanner/*" --remove coverage.total
    "*wazuh_modules/router/*" --remove coverage.total
    "*wazuh_modules/inventory_sync/*" --remove coverage.total
    "*wazuh_modules/content_manager/*" --remove coverage.total
    "*wazuh_modules/indexer_connector/*" --remove coverage.total
    "*wazuh_modules/src/wm_router.c" --remove coverage.total
    "*wazuh_modules/src/wm_content_manager.c" --remove coverage.total
    "*wazuh_modules/src/wm_inventory_sync.c" --remove coverage.total
    "*wazuh_modules/src/wm_vulnerability_scanner.c"
    ${TARGET_LCOV_EXTRA_REMOVE} --rc branch_coverage=1
    --ignore-errors mismatch,mismatch,unused,unused --output-file coverage.info.cleaned
  # Generate HTML report
  COMMAND
    ${GENHTML_PATH} -q --output-directory coverage-report --title
    "WAZUH unit-tests coverage" --rc branch_coverage=1 --ignore-errors
    mismatch,mismatch --legend coverage.info.cleaned
  # Clean counters
  COMMAND ${CMAKE_COMMAND} -E remove coverage.base coverage.total
          coverage.info.cleaned)

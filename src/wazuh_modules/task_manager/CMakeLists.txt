cmake_minimum_required(VERSION 3.12.4)

project(task_manager C CXX)

# Colocate the .so next to the other manager shared libs so modulesd's runtime rpath
# ($ORIGIN/../lib) resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB_RECURSE TASK_MANAGER_SRC "src/*.cpp")

# Compiled IN, not linked. os_cert_bundle.c is one function that probes the well-known CA bundle
# locations, and its own header records that it is deliberately dependency-free (plain POSIX stat(),
# no shared.h) precisely so a C++ module can compile it directly rather than link all of libwazuh --
# which this one must not do. The https_client module already does the same. Sharing the file keeps
# ONE list of candidate paths in the tree instead of a copy here that drifts from the original.
set(TASK_MANAGER_C_SRC ${SRC_FOLDER}/shared/src/os_cert_bundle.c)

add_library(task_manager SHARED ${TASK_MANAGER_SRC} ${TASK_MANAGER_C_SRC})

set_source_files_properties(${TASK_MANAGER_C_SRC} PROPERTIES COMPILE_OPTIONS "-fPIC")

# Pinned to 17 rather than inheriting the tree-wide 20: wazuh_uds_http_server declares a strict
# C++17 floor and pins its own translation units to it, and matching that keeps this module
# buildable in the same configurations its transport is.
set_target_properties(
  task_manager
  PROPERTIES CXX_STANDARD 17
             CXX_STANDARD_REQUIRED ON
             CXX_EXTENSIONS OFF
             BUILD_RPATH_USE_ORIGIN TRUE
             BUILD_RPATH "$ORIGIN/../lib")

target_compile_options(
  task_manager
  PRIVATE -Wall
          -Wextra
          -Wshadow
          -Wnon-virtual-dtor
          -Woverloaded-virtual
          -Wunused
          -Wcast-align
          -Wformat=2)

target_include_directories(
  task_manager
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
         # src/ is on the path so subsystems resolve by prefix -- "storage/...", "execution/...",
         # "handlers/..." -- which keeps the includes readable as the module grows.
         ${CMAKE_CURRENT_SOURCE_DIR}/src
  PRIVATE ${SRC_FOLDER}/shared_modules/utils # sqlite3Wrapper.hpp, loggerHelper.h, hashHelper.h
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/shared_modules/http-request/include # HTTPRequest.hpp, for the WPK client
          ${SRC_FOLDER}/shared/include # os_cert_bundle.h only -- NOT shared.h, and not libwazuh
          ${SRC_FOLDER}/shared_modules/uds_http_server/include
          ${SRC_FOLDER}/shared_modules/metrics/include
          ${SRC_FOLDER}/external/cJSON # pulled in by commonDefs.h
          ${SRC_FOLDER}/external/nlohmann
          ${SRC_FOLDER}/external/curl/include
          ${SRC_FOLDER}) # external/sqlite/sqlite3.h, as sqlite3Wrapper.hpp spells it

# NO libwazuh, deliberately. modulesd links the STATIC libwazuh, so a .so that also linked it would
# put a second copy of its globals in one process -- the same reason no other C++ module here links
# it. Everything this module would have needed from it arrives through the host-ops table.
#
# SQLite and libcurl both come from wazuhext, which bundles ext_sqlite and ext_curl whole-archive,
# so there is exactly one of each in the process and no new dependency is introduced.
#
# urlrequest is the tree's shared C++ HTTP client, already linked by vulnerability_scanner and
# indexer_connector. It is used ONLY for the outbound WPK-repository calls -- the module's own
# socket traffic keeps handlers/udsHttpClient, which needs libcurl error codes kept apart in a way
# this library does not offer. It takes curl from the same wazuhext, so it adds no new dependency.
target_link_libraries(
  task_manager
  PUBLIC wazuh_metrics
  PRIVATE pthread wazuh_uds_http_server urlrequest wazuhext)

# Built unconditionally, matching inventory_sync_server's testtool: the qa suite drives the real
# module through it, and gating it on UNIT_TEST would mean the integration job could not run without
# also building the unit tests.
add_subdirectory(testtool)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(task_manager)
  add_subdirectory(test)
endif()

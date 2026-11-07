# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(indexer_client)

# Indexer client: the process-wide runtime that replaced the v1 connector library (removed in 5.x;
# wazuh/wazuh#39933).

if(NOT DEFINED SRC_FOLDER)
  get_filename_component(SRC_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/../../ ABSOLUTE)
endif()

# Output layout of the shared modules (the v1, removed in 5.x, used it too): the standalone
# bundle and the installer pick shared modules up from ${CMAKE_BINARY_DIR}/lib.
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(Threads REQUIRED)

# The full source list is fixed here (E1 + the E2a transport + the E2b health and log sink + the E3a write path) so that the parallel steps never edit this file
# (plan 18, anexos/e2a-1/contrato-transport.md §Unidades).
set(INDEXER_CLIENT_SOURCES
    src/types.cpp
    src/config/runtimeConfig.cpp
    src/config/keyValueConfigSource.cpp
    src/runtime/runtime.cpp
    src/runtime/client.cpp
    src/runtime/tickets.cpp
    src/transport/transport.cpp
    src/transport/curlLoop.cpp
    src/transport/classify.cpp
    src/transport/retryAfter.cpp
    src/transport/tlsMaterial.cpp
    src/health/nodeSet.cpp
    src/health/prober.cpp
    src/log.cpp
    src/metrics.cpp
    src/runtime/logSummary.cpp
    src/write/encoding.cpp
    src/write/budget.cpp
    src/write/bucket.cpp
    src/write/scheduler.cpp
    src/write/sink.cpp
    src/write/writer.cpp
    src/write/response.cpp
    src/write/sender.cpp
    src/write/group.cpp
    src/query/query.cpp
    src/query/queryResponse.cpp
    src/query/pit.cpp
    src/query/pitRegistry.cpp)

# Two compilations of the same sources (I45b): the production objects behind the .so carry no test seam; the
# testing objects (INDEXER_CLIENT_TESTING + src/testing/) build a static library that only the component suite links,
# so no executable ever holds two copies of the runtime.
function(indexer_client_objects name)
  add_library(${name} OBJECT ${INDEXER_CLIENT_SOURCES} ${ARGN})
  # C++17 floor and pin, as uds_http_server (src/shared_modules/uds_http_server/CMakeLists.txt:16-17): the tree-wide
  # standard is 20, and strict-C++17 consumers must be able to include these headers.
  target_compile_features(${name} PUBLIC cxx_std_17)
  set_target_properties(${name} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON POSITION_INDEPENDENT_CODE ON)
  # curl's headers come from the vendored tree; curl and OpenSSL themselves only through wazuhext (I44): never link
  # ext_curl, the static archive, here.
  target_include_directories(
    ${name}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${SRC_FOLDER}/external/nlohmann
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
            ${SRC_FOLDER}/external/curl/include
            # loggerHelper.h (I56) and what it pulls in (commonDefs.h -> cJSON.h); never seen by the public headers.
            ${SRC_FOLDER}/shared_modules/utils
            ${SRC_FOLDER}/shared_modules/common
            ${SRC_FOLDER}/external/cJSON
            # The bulk-response classifier (E3b-1 I65); never seen by the public headers.
            ${SRC_FOLDER}/external/simdjson/include)
  # Only INDEXER_CLIENT_API symbols are exported. asio's headers force default visibility unless
  # ASIO_DISABLE_VISIBILITY is set (measured in the E0 spike: 159 asio symbols exported without it).
  target_compile_options(${name} PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
  target_compile_definitions(${name} PRIVATE ASIO_STANDALONE ASIO_DISABLE_VISIBILITY)
  # wazuhext on an OBJECT library links nothing: it brings the vendored OpenSSL's include path (and the build order) to
  # these sources. Without it a builder's older system headers turn sk_X509_INFO_* into sk_* symbols that the vendored
  # libcrypto does not export (D85).
  target_link_libraries(${name} PRIVATE ext_asio wazuhext)
endfunction()

indexer_client_objects(indexer_client_objects)
indexer_client_objects(indexer_client_objects_testing src/testing/seams.cpp src/testing/registry.cpp)
target_compile_definitions(indexer_client_objects_testing PUBLIC INDEXER_CLIENT_TESTING)

add_library(indexer_client SHARED $<TARGET_OBJECTS:indexer_client_objects>)
target_include_directories(indexer_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${SRC_FOLDER}/external/nlohmann)
target_compile_features(indexer_client PUBLIC cxx_std_17)
# --exclude-libs localizes whatever arrives from static archives; wazuhext is the process's single curl/OpenSSL (I44).
target_link_options(indexer_client PRIVATE "LINKER:--exclude-libs,ALL" "LINKER:--no-undefined")
# simdjson (the bulk-response classifier, E3b-1 I65): the prebuilt static archive (the v1, removed in 5.x,
# linked it too); its symbols stay local (--exclude-libs,ALL). Linked on the final targets: an OBJECT library's link
# does not reach $<TARGET_OBJECTS>.
set(INDEXER_CLIENT_SIMDJSON ${SRC_FOLDER}/external/simdjson/build/libsimdjson.a)
target_link_libraries(indexer_client PRIVATE wazuhext ext_asio Threads::Threads ${INDEXER_CLIENT_SIMDJSON})
set_target_properties(indexer_client PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE BUILD_RPATH "$ORIGIN/../lib")

# Test-only: the same sources with the seams compiled in. Configuration comes through IConfigSource only (I26c).
add_library(indexer_client_testing STATIC $<TARGET_OBJECTS:indexer_client_objects_testing>)
target_include_directories(
  indexer_client_testing PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include ${SRC_FOLDER}/external/nlohmann
                                ${CMAKE_CURRENT_SOURCE_DIR}/src ${SRC_FOLDER}/external/curl/include)
target_compile_definitions(indexer_client_testing PUBLIC INDEXER_CLIENT_TESTING)
target_compile_features(indexer_client_testing PUBLIC cxx_std_17)
target_link_libraries(indexer_client_testing PUBLIC wazuhext ext_asio Threads::Threads ${INDEXER_CLIENT_SIMDJSON})

if(UNIT_TEST)
  add_subdirectory(tests)
endif()

# Release benchmark harness of the transport and the write path (plan 18, E2c); off by default, never in the normal
# build. benchV1.cpp keeps the HTTPRequest::post loop of the v1 transport (the v1 connector library, removed in 5.x).
option(INDEXER_CLIENT_BENCH "Build the indexer_client benchmark harness" OFF)
if(INDEXER_CLIENT_BENCH)
  add_subdirectory(bench)
endif()

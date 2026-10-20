# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
# Benchmark harness (plan 18, E2c): the v1 bulk transport (HTTPRequest::post, SINGLE) and the v2 transport over the same
# in-process fake and the same libwazuhext. Built only with -DINDEXER_CLIENT_BENCH=ON, in Release. See README "Benchmark".

set(HTTP_REQUEST_DIR ${SRC_FOLDER}/shared_modules/http-request)

add_executable(indexer_client_bench_v1 benchV1.cpp)
target_include_directories(
  indexer_client_bench_v1
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../tests/fake ${HTTP_REQUEST_DIR}/include
          ${HTTP_REQUEST_DIR}/shared ${HTTP_REQUEST_DIR}/src ${SRC_FOLDER}/external/curl/include
          ${SRC_FOLDER}/external/nlohmann ${SRC_FOLDER} ${SRC_FOLDER}/external/openssl/include)
target_compile_definitions(indexer_client_bench_v1 PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_compile_features(indexer_client_bench_v1 PRIVATE cxx_std_17)
target_link_libraries(indexer_client_bench_v1 PRIVATE urlrequest wazuhext Threads::Threads)

# The production objects (no seams), linked statically: detail::runtimeTransport() is reachable.
add_executable(indexer_client_bench_v2 benchV2.cpp $<TARGET_OBJECTS:indexer_client_objects>)
target_include_directories(
  indexer_client_bench_v2
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../tests/fake ${CMAKE_CURRENT_SOURCE_DIR}/../include
          ${CMAKE_CURRENT_SOURCE_DIR}/../src ${SRC_FOLDER}/external/nlohmann ${SRC_FOLDER}/external/curl/include
          ${SRC_FOLDER} ${SRC_FOLDER}/external/openssl/include)
target_compile_definitions(indexer_client_bench_v2 PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT ASIO_STANDALONE)
target_compile_features(indexer_client_bench_v2 PRIVATE cxx_std_17)
target_link_libraries(indexer_client_bench_v2 PRIVATE wazuhext ext_asio Threads::Threads ${INDEXER_CLIENT_SIMDJSON})

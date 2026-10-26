# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
# Benchmark harness (plan 18, E2c): the v1 bulk transport (HTTPRequest::post, SINGLE) and the v2 transport over the same
# in-process fake and the same libwazuhext (indexer_client_bench_v2 --path client: the whole Client/bucket path, E6c).
# Built only with -DINDEXER_CLIENT_BENCH=ON, in Release. See README "Benchmark".

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

# D44 (plan 18, E5c): times classifyItems (simdjson ondemand) over synthetic 8 MiB bodies; no fake, no libwazuhext needed beyond the objects.
add_executable(indexer_client_bench_classify benchClassify.cpp $<TARGET_OBJECTS:indexer_client_objects>)
target_include_directories(
  indexer_client_bench_classify
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_SOURCE_DIR}/../src ${SRC_FOLDER}/external/nlohmann
          ${SRC_FOLDER}/external/simdjson/include ${SRC_FOLDER})
target_compile_definitions(indexer_client_bench_classify PRIVATE ASIO_STANDALONE)
target_compile_features(indexer_client_bench_classify PRIVATE cxx_std_17)
target_link_libraries(indexer_client_bench_classify PRIVATE wazuhext ext_asio Threads::Threads ${INDEXER_CLIENT_SIMDJSON})

# E6c (RNF-2, I119): the submit microbenchmark of the v2 write path (IWriter::post and IWriter::submit). The v1 side
# (the v1 async connector) was removed with the v1 library (E11d, I221).
add_executable(indexer_client_bench_submit benchSubmit.cpp $<TARGET_OBJECTS:indexer_client_objects>)
target_include_directories(
  indexer_client_bench_submit
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../include ${CMAKE_CURRENT_SOURCE_DIR}/../src
          ${SRC_FOLDER}/external/nlohmann ${SRC_FOLDER}/external/curl/include ${SRC_FOLDER}
          ${SRC_FOLDER}/external/openssl/include)
target_compile_definitions(indexer_client_bench_submit PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT ASIO_STANDALONE)
target_compile_features(indexer_client_bench_submit PRIVATE cxx_std_17)
target_link_libraries(indexer_client_bench_submit PRIVATE wazuhext ext_asio Threads::Threads ${INDEXER_CLIENT_SIMDJSON})

# D40 (plan 18, E6b): one target that builds the four harnesses (the CI bench job builds this one).
add_custom_target(indexer_client_bench DEPENDS indexer_client_bench_v1 indexer_client_bench_v2
                                               indexer_client_bench_classify indexer_client_bench_submit)

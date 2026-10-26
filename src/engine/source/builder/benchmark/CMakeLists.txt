# SPDX-License-Identifier: AGPL-3.0-or-later
# RNF-2 gate of the indexer output stage (plan 18, E10b, I198): the real `wazuh-indexer` stage over the v1 write path
# (a frozen copy of the 163d95c9ac wrapper, side v1) and over WIndexerConnector on the engine's indexer_client runtime
# (side v2), against the in-process fake of the indexer_client benches. Measure in Release (see run.sh). I208: the
# RNF-2 gate is now the engine's end-to-end A/B (E12); this stage ratio is reported as a diagnostic.
set(STAGE_BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/src)

add_executable(builder_stage_bench
    ${STAGE_BENCH_DIR}/stageBench.cpp
    ${STAGE_BENCH_DIR}/frozenV1Connector.cpp
)
# The indexer_client bench headers (benchFake.hpp, benchCommon.hpp) include <external/cpp-httplib/httplib.h>, hence the
# source root, last. Keystore::put comes from libindexer_connector.so (only the header, as wiconnector).
target_include_directories(builder_stage_bench
    PRIVATE
    ${STAGE_BENCH_DIR}
    ${SRC_DIR}
    ${INC_DIR}/builder
    ${SHARED_MODULES}/indexer_client/bench
    ${SHARED_MODULES}/keystore/include
    ${CMAKE_SOURCE_DIR}
)
target_compile_definitions(builder_stage_bench PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(builder_stage_bench
    PRIVATE
    builder
    wIndexerConnector::wIndexerConnector
    # Side v1: IndexerConnectorAsync and Keystore::put (libindexer_connector.so).
    indexer_connector
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

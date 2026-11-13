# SPDX-License-Identifier: AGPL-3.0-or-later
# Stage benchmark of the indexer output: the real `wazuh-indexer` stage over WIndexerConnector on
# the engine's indexer_client runtime, against the in-process fake of the indexer_client benches. Measure in Release
# (see run.sh). The performance gate is the engine's end-to-end A/B; this stage time is a diagnostic. The v1 side
# (a frozen copy of the v1 wrapper) was removed with the v1 library.
set(STAGE_BENCH_DIR ${CMAKE_CURRENT_LIST_DIR}/src)

add_executable(builder_stage_bench
    ${STAGE_BENCH_DIR}/stageBench.cpp
)
# The indexer_client bench headers (benchFake.hpp, benchCommon.hpp) include <external/cpp-httplib/httplib.h>, hence the
# source root, last.
target_include_directories(builder_stage_bench
    PRIVATE
    ${STAGE_BENCH_DIR}
    ${SRC_DIR}
    ${INC_DIR}/builder
    ${SHARED_MODULES}/indexer_client/bench
    ${CMAKE_SOURCE_DIR}
)
target_compile_definitions(builder_stage_bench PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_link_libraries(builder_stage_bench
    PRIVATE
    builder
    wIndexerConnector::wIndexerConnector
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

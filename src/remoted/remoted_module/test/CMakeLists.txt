cmake_minimum_required(VERSION 3.12.4)

project(remoted_module_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

file(GLOB UNIT_SRC_FILES ${UNIT_SRC_DIR}/*.cpp)

add_executable(remoted_module_utest ${UNIT_SRC_FILES})

target_link_libraries(
  remoted_module_utest
  debug gtestd
  debug gmockd
  debug gtest_maind
  debug gmock_maind
  optimized gtest
  optimized gmock
  optimized gtest_main
  optimized gmock_main
  remoted_module
  pthread
  # shutdownRace_test.cpp drives a real TLS client (asio::ssl) against a live RestinioHttpServer;
  # remoted_module links ssl/crypto PRIVATE (via ext_restinio), so this target needs its own link.
  ssl
  crypto
  # zstdDecoder_test.cpp's format-confusion test (a gzip stream fed to the zstd decoder) builds a
  # gzip fixture via zlib's deflate() directly (gzipTestHelper.hpp) -- production no longer uses
  # zlib at all (gzip support was removed), so this test-only need gets its own explicit link.
  ext_zlib
  # authGateway_test.cpp/zstdDecoder_test.cpp build zstd fixtures directly with ZSTD_compress();
  # remoted_module links ext_zstd PRIVATE, so this target needs its own link too.
  ext_zstd)

target_include_directories(
  remoted_module_utest
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${CMAKE_CURRENT_LIST_DIR}/../src # submodule headers by prefix: auth/, endpoints/, http_server/
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON
          # asioUdsHttpClient_test.cpp includes standalone-Asio headers directly; remoted_module
          # only gets them via ext_restinio, linked PRIVATE (not propagated to this target).
          ${SRC_FOLDER}/external/asio/include
          # statelessEndpoint_test.cpp includes RapidJSON headers directly; same PRIVATE-linkage gap.
          ${SRC_FOLDER}/external/rapidjson/include
          # control/*.hpp include "json.hpp" (nlohmann); remoted_module gets that dir PRIVATE so
          # the utest translation units need it added here too.
          ${SRC_FOLDER}/external/nlohmann
          # vdClient_test.cpp's fakeVdServer.hpp spins up a real httplib::Server over a UDS socket
          # to stand in for the VD module; remoted_module gets cpp-httplib PRIVATE, same gap as above.
          ${SRC_FOLDER}/external/cpp-httplib)

add_test(NAME remoted_module_utest COMMAND remoted_module_utest)
set_tests_properties(remoted_module_utest PROPERTIES LABELS remoted_module_utest)

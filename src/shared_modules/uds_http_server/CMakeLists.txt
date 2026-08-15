cmake_minimum_required(VERSION 3.12.4)

project(uds_http_server)

# Standalone-build support, same pattern as the other shared_modules.
if(NOT DEFINED SRC_FOLDER)
  get_filename_component(SRC_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/../../ ABSOLUTE)
endif()

add_library(wazuh_uds_http_server STATIC src/asioUdsHttpServer.cpp src/requestParser.cpp)

# Minimum 17 (the consumers include a strict-C++17 module: remoted_module); compiles unchanged
# under the tree-wide 20. The PUBLIC compile-feature is a FLOOR for consumers -- their own TUs
# keep their own standard -- while the archive's own TUs are PINNED to 17 below, so the promise
# is enforced on every build rather than trusted to review.
target_compile_features(wazuh_uds_http_server PUBLIC cxx_std_17)
set_target_properties(wazuh_uds_http_server PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

# Static lib archived into shared libs (inventory_sync_server, vulnerability_scanner,
# remoted_module). NEVER make this SHARED: Log::GLOBAL_LOG_FUNCTION has hidden per-DSO
# visibility (see loggerHelper.h), so the archive must resolve it inside each consumer .so for
# every copy to log through its own module's sink.
set_target_properties(wazuh_uds_http_server PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  wazuh_uds_http_server
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, proc.hpp
)

# Transport stays PRIVATE and confined behind the PImpl: no public header names asio or llhttp,
# which is what keeps makeUdsHttpServer() a one-line transport swap point.
target_link_libraries(wazuh_uds_http_server PRIVATE ext_asio ext_llhttp)

# Explicit rather than relying on asio's Boost auto-detection: nothing in this tree provides
# Boost, so leaving it to be inferred just makes the build depend on what happens to be installed.
target_compile_definitions(wazuh_uds_http_server PRIVATE ASIO_STANDALONE)

if(UNIT_TEST)
  set(BENCHMARK_TEST OFF)
  enable_testing()
  add_subdirectory(test)
endif()

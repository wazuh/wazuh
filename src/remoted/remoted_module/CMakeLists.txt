cmake_minimum_required(VERSION 3.12.4)

project(remoted_module CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Colocate the .so next to the other manager shared libs
# so remoted's runtime rpath ($ORIGIN/../lib) resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB_RECURSE REMOTED_MODULE_SRC "src/*.cpp")

add_library(remoted_module SHARED ${REMOTED_MODULE_SRC})

target_include_directories(
  remoted_module
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  # src/ is on the path so submodules resolve by prefix: "auth/...", "endpoints/...", "http_server/...".
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/external/cJSON # cJSON.h (pulled by commonDefs.h)
          ${SRC_FOLDER}/external/cpp-httplib # httplib.h (for UDS HTTP client)
          ${SRC_FOLDER}/external/nlohmann) # nlohmann/json.hpp

# ext_restinio pulls in ssl/crypto transitively (the shared jwt/ headers' EVP_MAC/EVP_KDF), so no explicit OpenSSL link
# is needed here. ext_rapidjson: header-only, used to parse /download request bodies.
# ext_zstd: zstdDecoder.cpp, for Content-Encoding: zstd request bodies.
# ext_jwt_cpp: header-only JWT (HS256) library behind the agent authentication profile.
# wazuh_metrics: the shared metric registry (shared_modules/metrics) behind control/metrics.hpp
# and scanvd/scanVdMetrics.hpp. Defined later in the top-level configure (this module never
# configures standalone), which is fine: CMake resolves link targets at generate time.
# wazuh_uds_http_server: the shared HTTP-over-UDS server behind the module's LOCAL admin socket
# (queue/sockets/remote-admin-http.sock, see startAdminServer() in remotedModuleFacade.hpp). Not
# registered by the top-level configure (its gate there never fires): the first consumer whose
# `if(NOT TARGET wazuh_uds_http_server)` guard runs registers it -- inventory_sync_server, under
# wazuh_modules, before remoted -- and the same guard below keeps this module independent of that
# order. Its asio/llhttp deps stay PRIVATE inside the archive, and it compiles the same vendored
# standalone asio (ASIO_STANDALONE) ext_restinio already uses.
# ca_bundle: shared_modules/ca_bundle, the CA bundle's parsing/hashing/guards (issue #39319), which
# the certs tool answers the same questions with. Its PUBLIC include directory propagates through
# this PRIVATE link, so http_server/ resolves <ca_bundle/ca_bundle.hpp> with nothing added below.
if(NOT TARGET wazuh_uds_http_server)
  add_subdirectory(${SRC_FOLDER}/shared_modules/uds_http_server
                   ${CMAKE_BINARY_DIR}/shared_modules/uds_http_server EXCLUDE_FROM_ALL)
endif()
target_link_libraries(remoted_module PRIVATE pthread ext_restinio ext_rapidjson ext_zstd ext_jwt_cpp
                                             wazuh_metrics wazuh_uds_http_server ca_bundle)

# The vendored asio compiled in this module's own TUs (RESTinio, the UDS client) would otherwise export
# its template instantiations and GNU-unique statics, which every DSO embedding asio in the same process
# binds to. --exclude-libs cannot reach them (no archive) and -fvisibility=hidden alone does not either
# (asio/detail/push_options.hpp pushes default visibility), so the version script localizes them by name.
target_link_options(remoted_module PRIVATE "LINKER:--version-script=${CMAKE_CURRENT_SOURCE_DIR}/remoted_module.map")
set_property(TARGET remoted_module APPEND PROPERTY LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/remoted_module.map)

set_target_properties(remoted_module PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_subdirectory(test)
endif()

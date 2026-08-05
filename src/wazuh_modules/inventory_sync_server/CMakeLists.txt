cmake_minimum_required(VERSION 3.12.4)

project(inventory_sync_server CXX)

# Colocate the .so next to the other manager shared libs (e.g. libinventory_sync.so)
# so modulesd's runtime rpath ($ORIGIN/../lib) resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB_RECURSE INVENTORY_SYNC_SERVER_SRC "src/*.cpp")

add_library(inventory_sync_server SHARED ${INVENTORY_SYNC_SERVER_SRC})

# FlatBuffers schema of the sync session (the FINAL wire contract, own copy under a distinct C++
# namespace until the legacy schema retires -- see schemas/inventorySyncSession.fbs). Generated into
# this module's binary dir, same pattern as shared_modules/sync_protocol: the legacy
# shared_modules/utils/flatbuffers/schemas/inventorySync.fbs is NOT touched.
set(FLATC_EXECUTABLE ${SRC_FOLDER}/external/flatbuffers/build/flatc)
set(INVENTORY_SYNC_SERVER_SCHEMA ${CMAKE_CURRENT_SOURCE_DIR}/schemas/inventorySyncSession.fbs)
set(INVENTORY_SYNC_SERVER_GENERATED_HEADER ${CMAKE_CURRENT_BINARY_DIR}/include/inventorySyncSession_generated.h)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/include)
add_custom_command(
  OUTPUT ${INVENTORY_SYNC_SERVER_GENERATED_HEADER}
  COMMAND ${FLATC_EXECUTABLE} --cpp -o ${CMAKE_CURRENT_BINARY_DIR}/include ${INVENTORY_SYNC_SERVER_SCHEMA}
          --no-warnings
  DEPENDS ${INVENTORY_SYNC_SERVER_SCHEMA}
  COMMENT "Generating inventory_sync_server FlatBuffers schema header"
  VERBATIM)
add_custom_target(generate_inventory_sync_server_schema DEPENDS ${INVENTORY_SYNC_SERVER_GENERATED_HEADER})
if(TARGET flatbuffers_external)
  add_dependencies(generate_inventory_sync_server_schema flatbuffers_external)
endif()
add_dependencies(inventory_sync_server generate_inventory_sync_server_schema)

# The VD adapter TU compiles the scanner's headers, which include the LEGACY generated schema; in
# a whole-project build that header is produced by this target (same guard as inventory_sync's).
if(TARGET compile_schemas_input)
  add_dependencies(inventory_sync_server compile_schemas_input)
endif()

target_include_directories(
  inventory_sync_server
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
         # Generated schema header + the header-only flatbuffers runtime it includes. PUBLIC so the
         # unit-test target inherits both through target_link_libraries.
         ${CMAKE_CURRENT_BINARY_DIR}/include
         ${SRC_FOLDER}/external/flatbuffers/include
  # src/ is on the path so submodules resolve by prefix: "http_server/...", "endpoints/...",
  # "common/...".
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp, proc.hpp
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/external/cJSON # cJSON.h (pulled by commonDefs.h)
          ${SRC_FOLDER}/external/nlohmann # json.hpp
          # ONLY for src/vd/vdScannerAdapter.cpp: the scanner facade's header transitively pulls
          # the legacy module's Context, the legacy generated schema, and headers spelled relative
          # to the source root ("external/nlohmann/json.hpp"). Contained to that one TU (see
          # vd/vdScannerFactory.hpp); goes away when the legacy module retires.
          ${SRC_FOLDER}/wazuh_modules/inventory_sync/src
          ${SRC_FOLDER})

# ext_asio: header-only standalone Asio (INTERFACE target). ext_llhttp: static HTTP parser.
# Both are linked PRIVATE and confined to the .cpp files behind the PImpl, so neither leaks
# into this module's public headers -- which is what keeps the transport swappable.
# Neither pulls in RESTinio, fmt or OpenSSL.
#
# wazuhext provides cJSON (bundled whole-archive, see external/CMakeLists.txt): the extern "C" shim
# calls cJSON_Print/cJSON_free to convert the borrowed <indexer> subtree. Taking it from the shared
# library rather than linking ext_cjson statically avoids a second copy of cJSON inside this .so,
# which would sit alongside the one modulesd already has loaded.
# vulnerability_scanner: the VD scan lane calls its neutral entry points (runScannerFromViews,
# the vd_sync coordination registry). The dependency is one-way -- the scanner never includes a
# header of this module -- so no cycle: the scanner's own coordination needs are served through
# vd_sync::IScanCoordinator implementations REGISTERED by the sync modules.
target_link_libraries(inventory_sync_server PRIVATE pthread ext_asio ext_llhttp wazuhext indexer_connector
                                                    vulnerability_scanner)

# Explicit rather than relying on asio's Boost auto-detection: nothing in this tree provides Boost,
# so leaving it to be inferred just makes the build depend on what happens to be installed.
target_compile_definitions(inventory_sync_server PRIVATE ASIO_STANDALONE)

set_target_properties(inventory_sync_server PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                      BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(inventory_sync_server)
  add_subdirectory(test)
endif()

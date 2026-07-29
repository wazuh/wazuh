cmake_minimum_required(VERSION 3.12.4)

project(inventory_sync_server CXX)

# Colocate the .so next to the other manager shared libs (e.g. libinventory_sync.so)
# so modulesd's runtime rpath ($ORIGIN/../lib) resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB_RECURSE INVENTORY_SYNC_SERVER_SRC "src/*.cpp")

add_library(inventory_sync_server SHARED ${INVENTORY_SYNC_SERVER_SRC})

target_include_directories(
  inventory_sync_server
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  # src/ is on the path so submodules resolve by prefix: "http_server/...", "endpoints/...",
  # "common/...".
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp, proc.hpp
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/external/cJSON # cJSON.h (pulled by commonDefs.h)
          ${SRC_FOLDER}/external/nlohmann) # json.hpp

# ext_asio: header-only standalone Asio (INTERFACE target). ext_llhttp: static HTTP parser.
# Both are linked PRIVATE and confined to the .cpp files behind the PImpl, so neither leaks
# into this module's public headers -- which is what keeps the transport swappable.
# Neither pulls in RESTinio, fmt or OpenSSL.
#
# wazuhext provides cJSON (bundled whole-archive, see external/CMakeLists.txt): the extern "C" shim
# calls cJSON_Print/cJSON_free to convert the borrowed <indexer> subtree. Taking it from the shared
# library rather than linking ext_cjson statically avoids a second copy of cJSON inside this .so,
# which would sit alongside the one modulesd already has loaded.
target_link_libraries(inventory_sync_server PRIVATE pthread ext_asio ext_llhttp wazuhext)

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

cmake_minimum_required(VERSION 3.12.4)
project(inventory_sync_server_testtool)

# The VD integration workflow's driver (replaces the legacy inventory_sync_testtool): starts the
# real vulnerability scanner + the real inventory_sync_server and POSTs FullSession buffers to the
# server's UDS /stateful route. See main.cpp.

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif()

add_executable(inventory_sync_server_testtool main.cpp)

target_include_directories(
  inventory_sync_server_testtool
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include # inventory_sync_server.h
          # vulnerabilityScannerFacade.hpp and headers spelled relative to the source root -- the
          # same set the module's own vdScannerAdapter.cpp needs.
          ${SRC_FOLDER}/wazuh_modules/vulnerability_scanner/include
          ${SRC_FOLDER}/wazuh_modules/vulnerability_scanner/src
          ${SRC_FOLDER}
          ${SRC_FOLDER}/shared_modules/utils # flatbuffers/include/inventorySync_generated.h
          ${SRC_FOLDER}/external/flatbuffers/include
          ${SRC_FOLDER}/external/nlohmann
          ${SRC_FOLDER}/external/cJSON
          ${SRC_FOLDER}/shared_modules/common)

if(TARGET compile_schemas_input)
  add_dependencies(inventory_sync_server_testtool compile_schemas_input)
endif()

target_link_libraries(inventory_sync_server_testtool inventory_sync_server vulnerability_scanner wazuhext pthread)

set_target_properties(
  inventory_sync_server_testtool PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                            "${CMAKE_BINARY_DIR}/bin")

cmake_minimum_required(VERSION 3.12.4)

project(indexer_connector)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if(NOT DEFINED SHARED_MODULES)
  get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(include)

include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/simdjson/include)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/openssl/include)

include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/common)
include_directories(${SHARED_MODULES}/http-request/include)
include_directories(${SHARED_MODULES}/keystore/include)

# Link directories
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)
link_directories(${SRC_FOLDER}/external/rocksdb/build)
link_directories(${SRC_FOLDER}/external/simdjson/build)
link_directories(${SHARED_MODULES}/http-request/build)
link_directories(${SHARED_MODULES}/keystore/build)

set(INDEXER_CONNECTOR_SRC src/indexerConnectorAsync.cpp
                          src/indexerConnectorSync.cpp)

add_library(indexer_connector SHARED ${INDEXER_CONNECTOR_SRC})

target_link_libraries(indexer_connector PRIVATE rocksdb urlrequest gcc_s
                                                wazuhext keystore simdjson)

set_target_properties(indexer_connector PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                   BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(indexer_connector)
  add_subdirectory(tests)
endif()

add_subdirectory(testtool)

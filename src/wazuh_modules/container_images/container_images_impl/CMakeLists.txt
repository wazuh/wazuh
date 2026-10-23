cmake_minimum_required(VERSION 3.12.4)

project(ContainerImagesImpl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1)
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)
link_directories(${CMAKE_BINARY_DIR}/lib)

include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/zlib/) # layer blob decompression
include_directories(${SRC_FOLDER}/external/zstd/lib/) # layer blob decompression
include_directories(${SRC_FOLDER}/external/curl/include/) # registry transport
include_directories(${SRC_FOLDER}/external/openssl/include/) # hash_helper
include_directories(${SRC_FOLDER}/external/sqlite/) # rpm sqlite database backend
# The rpm header and database format readers are the shared agent package reading. They
# are header only, so they are compiled here rather than linked, and the module gains no
# dependency on libsysinfo.
include_directories(${SRC_FOLDER}/data_provider/src/packages/)
include_directories(${SRC_FOLDER}/shared/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)

# Locate the shared dependencies, falling back to the target name for fresh builds.
find_library(
  DBSYNC_LIB dbsync
  HINTS ${CMAKE_BINARY_DIR}/lib
  NO_DEFAULT_PATH)
if(NOT DBSYNC_LIB)
  set(DBSYNC_LIB dbsync)
endif()

add_library(
  ContainerImagesImpl STATIC
  src/agent_credential_store.cpp
  src/container_images_impl.cpp
  src/container_images_db.cpp
  src/archive_image_reader.cpp
  src/auth_challenge.cpp
  src/ca_bundle.cpp
  src/byte_stream.cpp
  src/layer_composer.cpp
  src/layer_reader.cpp
  src/oci_metadata.cpp
  src/package_db_parser.cpp
  src/platform_selection.cpp
  src/registry_byte_stream.cpp
  src/registry_image_reader.cpp
  src/registry_reference.cpp
  src/registry_transport.cpp
  src/retry_policy.cpp)

set_target_properties(ContainerImagesImpl PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  ContainerImagesImpl
  PUBLIC include)

target_link_libraries(
  ContainerImagesImpl
  PRIVATE ${DBSYNC_LIB}
          wazuhext
          # zstd-compressed layers. Vendored and already built for every agent target,
          # so this adds a link line rather than a dependency.
          ext_zstd)

if(UNIT_TEST AND ("${TARGET}" STREQUAL "agent" OR "${TARGET}" STREQUAL
                                                  "winagent"))
  enable_testing()
  add_coverage_libraries(ContainerImagesImpl)
  add_subdirectory(tests)
endif()

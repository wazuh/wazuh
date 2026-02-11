cmake_minimum_required(VERSION 3.12.4)

project(AGENT_INFO_IMPL)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1)
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()
message(STATUS "SRC_FOLDER: ${SRC_FOLDER}")
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/libpcre2/.libs/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${CMAKE_BINARY_DIR}/lib)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/libpcre2/include)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/openssl/include/) # needed for
                                                             # hash_helper
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/wazuh_modules/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(
  ${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${CMAKE_BINARY_DIR}/shared_modules/sync_protocol/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/data_provider/include/)

find_library(
  FILESYSTEM_WRAPPER_LIB FilesystemWrapper
  HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib
  NO_DEFAULT_PATH)
find_library(
  FILE_IO_LIB FileIO
  HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib
  NO_DEFAULT_PATH)
find_library(
  DBSYNC_LIB dbsync
  HINTS ${SRC_FOLDER}/shared_modules/dbsync/build/lib
  NO_DEFAULT_PATH)
find_library(
  AGENT_METADATA_LIB agent_metadata
  HINTS ${SRC_FOLDER}/shared_modules/agent_metadata/build/lib
  NO_DEFAULT_PATH)
find_library(
  SYNC_PROTOCOL_LIB agent_sync_protocol
  HINTS ${CMAKE_BINARY_DIR}/lib
  NO_DEFAULT_PATH)
find_library(
  PCRE2_LIB pcre2-8
  HINTS ${SRC_FOLDER}/external/libpcre2/.libs
  NO_DEFAULT_PATH)
find_library(
  OPENSSL_LIB ssl
  HINTS ${SRC_FOLDER}/external/openssl
  NO_DEFAULT_PATH)
find_library(
  OPENSSL_CRYPTO_LIB crypto
  HINTS ${SRC_FOLDER}/external/openssl
  NO_DEFAULT_PATH)

# Set fallback values if libraries aren't found (for fresh builds)
if(NOT FILESYSTEM_WRAPPER_LIB)
  set(FILESYSTEM_WRAPPER_LIB FilesystemWrapper)
  message(STATUS "FilesystemWrapper library not found, using target name")
endif()
if(NOT FILE_IO_LIB)
  set(FILE_IO_LIB FileIO)
  message(STATUS "FileIO library not found, using target name")
endif()
if(NOT DBSYNC_LIB)
  set(DBSYNC_LIB dbsync)
  message(STATUS "dbsync library not found, using target name")
endif()
if(NOT AGENT_METADATA_LIB)
  set(AGENT_METADATA_LIB agent_metadata)
  message(STATUS "agent_metadata library not found, using target name")
endif()
if(NOT SYNC_PROTOCOL_LIB)
  set(SYNC_PROTOCOL_LIB agent_sync_protocol)
  message(STATUS "agent_sync_protocol library not found, using target name")
endif()
if(NOT PCRE2_LIB)
  set(PCRE2_LIB pcre2-8)
  message(STATUS "pcre2-8 library not found, using target name")
endif()

if(TARGET FileIO)
  set(FILE_IO_LIB FileIO)
endif()
if(TARGET FilesystemWrapper)
  set(FILESYSTEM_WRAPPER_LIB FilesystemWrapper)
endif()
if(TARGET dbsync)
  set(DBSYNC_LIB dbsync)
endif()
if(TARGET agent_metadata)
  set(AGENT_METADATA_LIB agent_metadata)
endif()
if(TARGET agent_sync_protocol)
  set(SYNC_PROTOCOL_LIB agent_sync_protocol)
endif()

add_library(AGENT_INFO_IMPL STATIC src/agent_info_impl.cpp)
# ${SRC_FOLDER}/${RESOURCE_OBJ})

# Set position independent code for static library to be linked into shared
# library
set_target_properties(AGENT_INFO_IMPL PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(
  AGENT_INFO_IMPL
  PUBLIC include
  PRIVATE src)
target_compile_definitions(AGENT_INFO_IMPL PRIVATE PCRE2_STATIC
                                                   PCRE2_CODE_UNIT_WIDTH=8)
target_link_libraries(
  AGENT_INFO_IMPL
  PUBLIC ${FILE_IO_LIB}
  PRIVATE sysinfo
          ${FILESYSTEM_WRAPPER_LIB}
          ${AGENT_METADATA_LIB}
          ${SYNC_PROTOCOL_LIB}
          ${DBSYNC_LIB}
          wazuhext # contains hash_helper, string_helper, time_helper utilities
          cjson
          ${PCRE2_LIB}
          ${OPENSSL_LIB}
          ${OPENSSL_CRYPTO_LIB})

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(AGENT_INFO_IMPL)
  add_subdirectory(tests)
endif()

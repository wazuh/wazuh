cmake_minimum_required(VERSION 3.12.4)

project(Wazuh)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Coverity static analysis compatibility
if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

# Compiler flags for Debug and Release builds
if(NOT FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif()

# Sanitizer flags (override DEBUG flags when enabled)
if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

# Function to link coverage libraries for unit tests
# Uses plain signature for compatibility with existing plain signature usage
function(add_coverage_libraries target_name)
  if(UNIT_TEST)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      target_compile_options(${target_name} PUBLIC --coverage)
      target_link_libraries(${target_name} PUBLIC -fprofile-arcs)
    else()
      target_compile_options(${target_name} PUBLIC --coverage)
      target_link_libraries(${target_name} PUBLIC gcov)
    endif()
  endif()
endfunction()

# SRC_FOLDER should point to the src/ directory Sub-modules will try to redefine
# it, so we set a guard variable
set(SRC_FOLDER ${CMAKE_SOURCE_DIR})
set(WAZUH_MAIN_PROJECT
    ON
    CACHE BOOL "Main Wazuh CMake project" FORCE)

# Define CLIENT for agent builds
if("${TARGET}" STREQUAL "winagent" OR "${TARGET}" STREQUAL "agent")
  add_definitions(-DCLIENT)
endif()

# Define WAZUH_MANAGER for manager builds
if("${TARGET}" STREQUAL "server")
  add_definitions(-DWAZUH_MANAGER)
endif()

# Set Wine as crosscompiling emulator for Windows unit tests
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND UNIT_TEST)
  find_program(WINE "wine")
  if(NOT WINE)
    message(WARNING "Wine is required to run Windows tests on Linux")
  endif()
  set(CMAKE_CROSSCOMPILING_EMULATOR wine)
endif()

# ##############################################################################
# External dependencies
# ##############################################################################
function(check_and_download_dep libname url)
  if(NOT EXISTS ${SRC_FOLDER}/external/${libname})
    message("==============================================")

    # Download library from S3 bucket
    message("Downloading ${libname}...")
    file(
      DOWNLOAD ${url}/${libname}.tar.gz ${SRC_FOLDER}/external/${libname}.tar.gz
      TIMEOUT 60 # seconds
      STATUS DOWNLOAD_STATUS)
    list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
    list(GET DOWNLOAD_STATUS 1 STATUS_MESSAGE)
    if(NOT STATUS_CODE EQUAL 0)
      message(
        FATAL_ERROR
          "Error downloading ${libname}: ${STATUS_MESSAGE} (${STATUS_CODE}).")
    endif(NOT STATUS_CODE EQUAL 0)

    # Extract library
    message("Extracting ${libname}.tar.gz")
    execute_process(
      COMMAND ${CMAKE_COMMAND} -E tar xfz
              "${SRC_FOLDER}/external/${libname}.tar.gz"
      WORKING_DIRECTORY ${SRC_FOLDER}/external
      RESULT_VARIABLE STATUS_VALUE)
    if(NOT STATUS_VALUE EQUAL 0)
      message(FATAL_ERROR "Error extracting ${libname}: ${STATUS_VALUE}.")
    endif(NOT STATUS_VALUE EQUAL 0)

    # Cleanup tar file
    message("Cleaning ${libname}.tar.gz")
    file(REMOVE ${SRC_FOLDER}/external/${libname}.tar.gz)
  endif()
endfunction(check_and_download_dep)

set(EXTERNAL_RES nlohmann googletest benchmark cpp-httplib)

if(NOT EXTERNAL_DEPS_VERSION)
  set(EXTERNAL_DEPS_VERSION "21")
endif(NOT EXTERNAL_DEPS_VERSION)

if(NOT RESOURCES_URL)
  set(RESOURCES_URL
      "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/sources"
  )
endif(NOT RESOURCES_URL)

if(NOT PRECOMPILED_RESOURCES_URL)
  set(PRECOMPILED_RESOURCES_URL
      "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/linux/amd64"
  )
endif(NOT PRECOMPILED_RESOURCES_URL)

# Download external libraries
foreach(loop_var ${EXTERNAL_RES})
  check_and_download_dep(${loop_var} ${RESOURCES_URL})
endforeach(loop_var)

# Read the VERSION JSON file
file(READ "${SRC_FOLDER}/../VERSION.json" VERSION_JSON)

# Extract "version"
string(REGEX MATCH "\"version\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(VERSION_FILE "v${CMAKE_MATCH_1}") # <-- Add "v" prefix since old VERSION
                                      # file had it

# Extract "stage" as revision
string(REGEX MATCH "\"stage\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(REVISION_FILE "${CMAKE_MATCH_1}")

# Define preprocessor macros
add_definitions(-DVERSION="${VERSION_FILE}")
add_definitions(-DREVISION="${REVISION_FILE}")

# If REVISION OR FILE is empty fail
if("${REVISION_FILE}" STREQUAL "")
  message(FATAL_ERROR "REVISION file is empty")
endif("${REVISION_FILE}" STREQUAL "")

if("${VERSION_FILE}" STREQUAL "")
  message(FATAL_ERROR "VERSION file is empty")
endif("${VERSION_FILE}" STREQUAL "")

message("==============================================")
message("Wazuh version: ${VERSION_FILE}")
message("Wazuh revision: ${REVISION_FILE}")
message("==============================================")

set(BENCHMARK_ENABLE_TESTING "OFF")

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/rocksdb/build/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/lzma/build/)
link_directories(${SRC_FOLDER}/external/zlib/)
link_directories(${SRC_FOLDER}/external/zlib/contrib/minizip/)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${SRC_FOLDER}/external/simdjson/build/)

# Wazuh headers
include_directories(${SRC_FOLDER}/headers)

# Shared modules includes
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include)
include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/include)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include)
include_directories(${SRC_FOLDER}/shared_modules/http-request/include)
include_directories(${SRC_FOLDER}/shared_modules/indexer_connector/include)
include_directories(${SRC_FOLDER}/shared_modules/keystore/include)
include_directories(${SRC_FOLDER}/shared_modules/router/include)
include_directories(${SRC_FOLDER}/shared_modules/schema_validator/include)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include)
include_directories(${SRC_FOLDER}/shared_modules/utils)

# External dependencies includes
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/cpp-httplib)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)
include_directories(${SRC_FOLDER}/external/lzma/src/liblzma/api)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/simdjson/include/)
include_directories(${SRC_FOLDER}/external/zlib/)
include_directories(${SRC_FOLDER}/external/zlib/contrib/)

# Data Provider
add_subdirectory(data_provider)

# Engine - Server only
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  add_subdirectory(engine)
endif()

# Shared Modules
add_subdirectory(shared_modules/agent_metadata)
add_subdirectory(shared_modules/dbsync)
add_subdirectory(shared_modules/file_helper)
set(CURL_DEP wazuhext)
add_subdirectory(shared_modules/http-request)
add_subdirectory(shared_modules/schema_validator)
add_subdirectory(shared_modules/sync_protocol)
add_subdirectory(shared_modules/utils)

# Shared Modules - Server only
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  add_subdirectory(shared_modules/content_manager)
  add_subdirectory(shared_modules/indexer_connector)
  add_subdirectory(shared_modules/keystore)
  add_subdirectory(shared_modules/router)
endif()

# Syscheckd
add_subdirectory(syscheckd)

# Wazuh Modules
add_subdirectory(wazuh_modules/agent_info)
add_subdirectory(wazuh_modules/sca)
if(ENABLE_SYSC)
  add_subdirectory(wazuh_modules/syscollector)
endif()

# Wazuh Modules - Server only
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  add_subdirectory(wazuh_modules/inventory_sync)
  add_subdirectory(wazuh_modules/vulnerability_scanner)
endif()

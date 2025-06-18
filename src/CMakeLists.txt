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

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)

################################
# External dependencies
################################
function(check_and_download_dep libname url)
    if(NOT EXISTS ${SRC_FOLDER}/external/${libname})
        message("==============================================")

        # Download library from S3 bucket
        message("Downloading ${libname}...")
        file(DOWNLOAD ${url}/${libname}.tar.gz ${SRC_FOLDER}/external/${libname}.tar.gz
                TIMEOUT 60  # seconds
                STATUS DOWNLOAD_STATUS)
        list(GET DOWNLOAD_STATUS 0 STATUS_CODE)
        list(GET DOWNLOAD_STATUS 1 STATUS_MESSAGE)
        if(NOT STATUS_CODE EQUAL 0)
            message(FATAL_ERROR "Error downloading ${libname}: ${STATUS_MESSAGE} (${STATUS_CODE}).")
        endif(NOT STATUS_CODE EQUAL 0)

        # Extract library
        message("Extracting ${libname}.tar.gz")
        execute_process(COMMAND ${CMAKE_COMMAND} -E tar xfz "${SRC_FOLDER}/external/${libname}.tar.gz" WORKING_DIRECTORY ${SRC_FOLDER}/external RESULT_VARIABLE STATUS_VALUE)
        if(NOT STATUS_VALUE EQUAL 0)
            message(FATAL_ERROR "Error extracting ${libname}: ${STATUS_VALUE}.")
        endif(NOT STATUS_VALUE EQUAL 0)

        # Cleanup tar file
        message("Cleaning ${libname}.tar.gz")
        file(REMOVE ${SRC_FOLDER}/external/${libname}.tar.gz)
    endif()
endfunction(check_and_download_dep)

set(EXTERNAL_RES
    nlohmann
    googletest
    benchmark
    cpp-httplib
    )

if(NOT EXTERNAL_DEPS_VERSION)
    set(EXTERNAL_DEPS_VERSION "21")
endif(NOT EXTERNAL_DEPS_VERSION)

if(NOT RESOURCES_URL)
    set(RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/sources")
endif(NOT RESOURCES_URL)

if(NOT PRECOMPILED_RESOURCES_URL)
    set(PRECOMPILED_RESOURCES_URL "https://packages.wazuh.com/deps/${EXTERNAL_DEPS_VERSION}/libraries/linux/amd64")
endif(NOT PRECOMPILED_RESOURCES_URL)

# Download external libraries
foreach(loop_var ${EXTERNAL_RES})
    check_and_download_dep(${loop_var} ${RESOURCES_URL})
endforeach(loop_var)

# Read the VERSION JSON file
file(READ "${SRC_FOLDER}/../VERSION.json" VERSION_JSON)

# Extract "version"
string(REGEX MATCH "\"version\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(VERSION_FILE "v${CMAKE_MATCH_1}")  # <-- Add "v" prefix since old VERSION file had it

# Extract "stage" as revision
string(REGEX MATCH "\"stage\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(REVISION_FILE "${CMAKE_MATCH_1}")

# Define preprocessor macros
add_definitions(-DVERSION="${VERSION_FILE}")
add_definitions(-DREVISION="${REVISION_FILE}")

## If REVISION OR FILE is empty fail
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
link_directories(${SRC_FOLDER}/external/spdlog-1_14_1/spdlog-1.14.1/build/)
link_directories(${SRC_FOLDER}/external/gtest-1_15_0/googletest-1.15.0/build/)
link_directories(${SRC_FOLDER}/external/yaml-cpp-0.8.0/build/)
link_directories(${SRC_FOLDER}/external/pugixml-1_15/pugixml-1.15/build/)
link_directories(${SRC_FOLDER}/external/fmt/fmt-8.1.1)

include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/router/include)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/include)
include_directories(${SRC_FOLDER}/shared_modules/indexer_connector/include)
include_directories(${SRC_FOLDER}/shared_modules/http-request/include)
include_directories(${SRC_FOLDER}/shared_modules/keystore/include)
include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/spdlog-1_14_1/spdlog-1.14.1/include)
# include_directories(${SRC_FOLDER}/external/googletest/googletest/include)
# include_directories(${SRC_FOLDER}/external/googletest/googlemock/include)
# include_directories(${SRC_FOLDER}/external/gtest-1_15_0/googletest-1.15.0/googletest/include)
# include_directories(${SRC_FOLDER}/external/gtest-1_15_0/googletest-1.15.0/googlemock/include)
# include_directories(${SRC_FOLDER}/external/opentelemetry-cpp-1_8_3/opentelemetry-cpp-1.8.3/sdk/include)
include_directories(${SRC_FOLDER}/external/yaml-cpp-0.8.0/include)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/lzma/src/liblzma/api)
include_directories(${SRC_FOLDER}/external/zlib/)
include_directories(${SRC_FOLDER}/external/zlib/contrib/)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)

add_subdirectory(shared_modules/utils)
add_subdirectory(shared_modules/router)
add_subdirectory(shared_modules/content_manager)

set(CURL_DEP wazuhext)
add_subdirectory(shared_modules/http-request)
add_subdirectory(shared_modules/indexer_connector)
add_subdirectory(wazuh_modules/vulnerability_scanner)
add_subdirectory(shared_modules/keystore)
add_subdirectory(wazuh_modules/inventory_harvester)
add_subdirectory(engine)

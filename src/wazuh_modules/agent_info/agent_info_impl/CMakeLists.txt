cmake_minimum_required(VERSION 3.12.4)

project(AGENT_INFO_IMPL)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")
endif(FSANITIZE)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_definitions(-DWIN32=1)
endif()

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
message(STATUS "SRC_FOLDER: ${SRC_FOLDER}")
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/libpcre2/.libs/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/lib)
link_directories(${SRC_FOLDER}/data_provider/build)
link_directories(${SRC_FOLDER}/data_provider/build/lib)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/libpcre2/include)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/openssl/include/) # needed for hash_helper
include_directories(${SRC_FOLDER}/external/flatbuffers/include)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/wazuh_modules/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/build/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/data_provider/include/)

find_library(FILESYSTEM_WRAPPER_LIB FilesystemWrapper
    HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib
    NO_DEFAULT_PATH)
find_library(FILE_IO_LIB FileIO
    HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib
    NO_DEFAULT_PATH)
find_library(DBSYNC_LIB dbsync
    HINTS ${SRC_FOLDER}/shared_modules/dbsync/build/lib
    NO_DEFAULT_PATH)
find_library(SYNC_PROTOCOL_LIB agent_sync_protocol
    HINTS ${SRC_FOLDER}/shared_modules/sync_protocol/build/lib
    NO_DEFAULT_PATH)
find_library(PCRE2_LIB pcre2-8
    HINTS ${SRC_FOLDER}/external/libpcre2/.libs
    NO_DEFAULT_PATH)
find_library(OPENSSL_LIB ssl
    HINTS ${SRC_FOLDER}/external/openssl
    NO_DEFAULT_PATH)
find_library(OPENSSL_CRYPTO_LIB crypto
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
if(NOT SYNC_PROTOCOL_LIB)
    set(SYNC_PROTOCOL_LIB agent_sync_protocol)
    message(STATUS "agent_sync_protocol library not found, using target name")
endif()
if(NOT PCRE2_LIB)
    set(PCRE2_LIB pcre2-8)
    message(STATUS "pcre2-8 library not found, using target name")
endif()

add_library(
    AGENT_INFO_IMPL STATIC
    src/agent_info_impl.cpp)
    # ${SRC_FOLDER}/${RESOURCE_OBJ})

# Set position independent code for static library to be linked into shared library
set_target_properties(AGENT_INFO_IMPL PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_include_directories(AGENT_INFO_IMPL PUBLIC include PRIVATE src)
target_compile_definitions(AGENT_INFO_IMPL PRIVATE PCRE2_STATIC PCRE2_CODE_UNIT_WIDTH=8)
target_link_libraries(
    AGENT_INFO_IMPL
    PRIVATE
            sysinfo
            ${FILESYSTEM_WRAPPER_LIB}
            ${FILE_IO_LIB}
            ${SYNC_PROTOCOL_LIB}
            ${DBSYNC_LIB}
            wazuhext # contains hash_helper, string_helper, time_helper utilities
            cjson
            ${PCRE2_LIB}
            ${OPENSSL_LIB}
            ${OPENSSL_CRYPTO_LIB}
)

if(UNIT_TEST)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(AGENT_INFO_IMPL PRIVATE -fprofile-arcs -ftest-coverage)
        target_link_libraries(AGENT_INFO_IMPL PRIVATE -fprofile-arcs)
    else()
        target_compile_options(AGENT_INFO_IMPL PRIVATE --coverage)
        target_link_libraries(AGENT_INFO_IMPL PRIVATE gcov)
    endif()

    enable_testing()
    add_subdirectory(tests)
endif()

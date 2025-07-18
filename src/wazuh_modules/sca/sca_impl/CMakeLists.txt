cmake_minimum_required(VERSION 3.22)

project(SCAImpl)

# compile with C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_definitions(-DWIN32=1)
endif()

# find_package(pcre2 CONFIG REQUIRED)
# find_package(yaml CONFIG REQUIRED)
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
message(STATUS "SRC_FOLDER: ${SRC_FOLDER}")
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/libpcre2/.libs/)
link_directories(${SRC_FOLDER}/external/libyaml/src/.libs/)
link_directories(${SRC_FOLDER}/external/openssl/)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/data_provider/build)
link_directories(${SRC_FOLDER}/data_provider/build/lib)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/libpcre2/include)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/libyaml/include)
include_directories(${SRC_FOLDER}/external/openssl/include/) # needed for hash_helper
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/data_provider/include/)

# Dependencies should be built externally and made available
# Use find_library to locate dependencies, but fall back to target names if not found

find_library(FILESYSTEM_WRAPPER_LIB FilesystemWrapper
    HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib
    NO_DEFAULT_PATH)
find_library(FILE_IO_LIB FileIO
    HINTS ${SRC_FOLDER}/shared_modules/file_helper/build/lib
    NO_DEFAULT_PATH)
find_library(DBSYNC_LIB dbsync
    HINTS ${SRC_FOLDER}/shared_modules/dbsync/build/lib
    NO_DEFAULT_PATH)
find_library(SYSINFO_LIB sysinfo
    HINTS ${SRC_FOLDER}/data_provider/build/lib
    NO_DEFAULT_PATH)
find_library(YAML_LIB yaml
    HINTS ${SRC_FOLDER}/external/libyaml/src/.libs
    NO_DEFAULT_PATH)
find_library(PCRE2_LIB pcre2-8
    HINTS ${SRC_FOLDER}/external/libpcre2/.libs
    NO_DEFAULT_PATH)
find_library(OPENSSL_LIB ssl
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
if(NOT SYSINFO_LIB)
    set(SYSINFO_LIB sysinfo)
    message(STATUS "sysinfo library not found, using target name")
endif()
if(NOT YAML_LIB)
    set(YAML_LIB yaml)
    message(STATUS "yaml library not found, using target name")
endif()
if(NOT PCRE2_LIB)
    set(PCRE2_LIB pcre2-8)
    message(STATUS "pcre2-8 library not found, using target name")
endif()

add_library(
    SCAImpl STATIC
    src/sca_impl.cpp
    src/yaml_document.cpp
    src/yaml_node.cpp
    src/sca_policy.cpp
    src/sca_policy_check.cpp
    src/sca_policy_loader.cpp
    src/sca_policy_parser.cpp
    src/sca_event_handler.cpp
    src/sca_utils.cpp
    src/check_condition_evaluator.cpp
    $<$<PLATFORM_ID:Windows>:src/sca_policy_check_win.cpp>
    ${SRC_FOLDER}/${RESOURCE_OBJ})

target_include_directories(SCAImpl PUBLIC include PRIVATE src)

target_compile_definitions(SCAImpl PRIVATE PCRE2_CODE_UNIT_WIDTH=8)

target_link_libraries(
    SCAImpl
    PRIVATE ${FILESYSTEM_WRAPPER_LIB}
            ${FILE_IO_LIB}
            ${DBSYNC_LIB}
            ${SYSINFO_LIB}
            wazuhext # contains hash_helper, string_helper, time_helper utilities
            cjson
            ${YAML_LIB}
            ${PCRE2_LIB}
            ${OPENSSL_LIB}
)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

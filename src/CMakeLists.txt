cmake_minimum_required(VERSION 3.12.4)
project(Wazuh)

get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/ ABSOLUTE)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/procps/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/curl/include/curl/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/libplist/bin/include/)
include_directories(${SRC_FOLDER}/external/libdb/build_unix/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
if(NOT CMAKE_CHECK_CENTOS5) # Avoid incompatible libraries in CentOS 5 and Red Hat 5
include_directories(${SRC_FOLDER}/external/pacman/lib/libalpm/)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)
endif(NOT CMAKE_CHECK_CENTOS5)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++17 -g")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif(UNIX AND NOT APPLE)

string (REGEX MATCH "\\.el[1-9]" os_version_suffix ${CMAKE_SYSTEM})
if(os_version_suffix STREQUAL ".el5")
    set(CENTOS5 TRUE)
endif(os_version_suffix STREQUAL ".el5")


add_subdirectory("shared_modules/urlRequest")

if(${TARGET} STREQUAL "agent")
    message("Agent")
elseif(${TARGET} STREQUAL "winagent")
    message("winagent")
elseif(${TARGET} STREQUAL "manager" OR ${TARGET} STREQUAL "server")
    message("manager")
elseif (${TARGET} STREQUAL "content")
    message("======== content ========")
    add_subdirectory("vulnerability_detector")
    add_subdirectory("content")
else ()
    message(FATAL_ERROR "Incorrect target type")
endif(${TARGET} STREQUAL "agent")



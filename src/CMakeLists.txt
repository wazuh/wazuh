cmake_minimum_required(VERSION 3.9.6)
project(Wazuh)

include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/procps/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/external/libplist/bin/include/)
include_directories(${SRC_FOLDER}/external/libdb/build_unix/)
if(NOT CMAKE_CHECK_CENTOS5) # Avoid incompatible libraries in CentOS 5 and Red Hat 5
include_directories(${SRC_FOLDER}/external/pacman/lib/libalpm/)
include_directories(${SRC_FOLDER}/external/libarchive/libarchive/)
endif(NOT CMAKE_CHECK_CENTOS5)

add_subdirectory(wazuhext)

if(UNIX AND NOT APPLE)
    set(LINUX TRUE)
endif(UNIX AND NOT APPLE)

string (REGEX MATCH "\\.el[1-9]" os_version_suffix ${CMAKE_SYSTEM})
if(os_version_suffix STREQUAL ".el5")
    set(CENTOS5 TRUE)
endif(os_version_suffix STREQUAL ".el5")

if(TARGET STREQUAL "agent")
    message("Agent")
elseif(TARGET STREQUAL "winagent")
    message("winagent")
elseif(TARGET STREQUAL "manager" OR TARGET STREQUAL "server")
    message("manager")
else ()
    message(FATAL_ERROR "Incorrect target type")
endif(TARGET STREQUAL "agent")


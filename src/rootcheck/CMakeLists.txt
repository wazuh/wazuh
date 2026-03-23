cmake_minimum_required(VERSION 3.12.4)

project(wazuh-rootcheck C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/shared/include/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/external/curl/include/curl/)
include_directories(${SRC_FOLDER}/external/libpcre2/include/)
include_directories(${SRC_FOLDER}/external/libyaml/include/)
include_directories(${SRC_FOLDER}/external/libplist/bin/include/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/config/include)
include_directories(${SRC_FOLDER}/shared/include/error_messages)
include_directories(${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256)
include_directories(${SRC_FOLDER}/shared/os_crypto/sha1)
include_directories(${SRC_FOLDER}/shared/os_net/)
include_directories(${SRC_FOLDER}/shared/os_regex/)
include_directories(${SRC_FOLDER}/shared/os_xml/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include)
include_directories(${SRC_FOLDER}/syscheckd/include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_definitions(-DARGV0="wazuh-rootcheck")
add_definitions(-DGROUPGLOBAL=wazuh)
add_definitions(-DOSSECHIDS)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -DWIN_EXPORT)
endif()

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

file(GLOB ROOTCHECK_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

add_library(rootcheck STATIC ${ROOTCHECK_SRC})
set_target_properties(rootcheck PROPERTIES LINKER_LANGUAGE C)
target_link_libraries(rootcheck PUBLIC wazuhext pthread config wazuh)

cmake_minimum_required(VERSION 3.12.4)

project(wazuh-authd C CXX)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
  list(APPEND CMAKE_MODULE_PATH "${SRC_FOLDER}/cmake")
  include(WazuhRpath)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
  ${SRC_FOLDER}/shared/os_crypto/md5/
  ${SRC_FOLDER}/shared/os_crypto/md5_sha1_sha256/
  ${SRC_FOLDER}/shared/os_crypto/sha1/
  ${SRC_FOLDER}/shared/os_crypto/signature/
  ${SRC_FOLDER}/shared/include/error_messages/
  ${SRC_FOLDER}/external/cJSON/
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/libyaml/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/openssl/include/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_db/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/include/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(WAZUH_RUNTIME_GROUP "wazuh")
set(WAZUH_RUNTIME_USER "wazuh")
if(NOT "${TARGET}" STREQUAL "winagent" AND NOT "${TARGET}" STREQUAL "agent")
  set(WAZUH_RUNTIME_GROUP "wazuh-manager")
  set(WAZUH_RUNTIME_USER "wazuh-manager")
endif()

add_definitions(-DARGV0="wazuh-manager-authd")
add_definitions(-DGROUPGLOBAL="${WAZUH_RUNTIME_GROUP}")
add_definitions(-DUSER="${WAZUH_RUNTIME_USER}")

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# Collect source files
file(GLOB AUTHD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
# The re-enrollment bridge (issue #38993) is authd's one C++ file: a thin extern "C" wrapper over the
# header-only verifier in shared_modules/utils/jwt/, so authd judges the agent's `wazuh-enroll+jwt`
# bearer with the very code remoted and the agent use. Listed explicitly: the GLOB above is *.c on
# purpose, and a second GLOB would silently pick up any future .cpp.
list(APPEND AUTHD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/reenroll_verify.cpp")

# Build static library (without main-server.c) for unit tests
list(REMOVE_ITEM AUTHD_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main-server.c")
add_library(authd_lib STATIC ${AUTHD_SRC})
# CXX, not C, since reenroll_verify.cpp joined: a consumer that links this archive needs the C++
# runtime (the daemon below already links as CXX; the cmocka tests add -lstdc++ themselves).
set_target_properties(authd_lib PROPERTIES LINKER_LANGUAGE CXX)
target_compile_features(authd_lib PRIVATE cxx_std_17)
# shared_modules/utils/jwt/*.hpp and their header-only dependencies (jwt-cpp, rapidjson). The jwt-cpp
# headers are taken from ext_jwt_cpp's usage requirements WITHOUT linking that target: it also carries
# the static libcrypto.a, and linking it here would put a second OpenSSL inside authd next to the one
# libwazuhext.so already provides (the HMAC/HKDF calls resolve to wazuhext's, like the rest of authd).
target_include_directories(authd_lib PRIVATE ${SRC_FOLDER}/shared_modules/utils)
if(TARGET ext_jwt_cpp)
  target_include_directories(authd_lib SYSTEM PRIVATE
                             $<TARGET_PROPERTY:ext_jwt_cpp,INTERFACE_INCLUDE_DIRECTORIES>)
  target_compile_definitions(authd_lib PRIVATE $<TARGET_PROPERTY:ext_jwt_cpp,INTERFACE_COMPILE_DEFINITIONS>)
  target_link_libraries(authd_lib PUBLIC ext_rapidjson)
else()
  # Standalone configure of this directory (no external/): the same headers by path.
  target_include_directories(authd_lib SYSTEM PRIVATE ${SRC_FOLDER}/external/jwt-cpp/include
                                                     ${SRC_FOLDER}/external
                                                     ${SRC_FOLDER}/external/rapidjson/include)
  target_compile_definitions(authd_lib PRIVATE JWT_DISABLE_PICOJSON)
endif()

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(authd_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_options(authd_lib PRIVATE -O0 -g)
endif()

target_link_libraries(authd_lib PUBLIC wazuhext pthread config
                                       wazuh_modulesd_lib wazuh)

if(UNIX)
  target_link_libraries(authd_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(authd_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Only build Unix executable when not running unit tests (server-only, no
# Windows)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT UNIT_TEST)
  add_executable(wazuh-manager-authd
                 "${CMAKE_CURRENT_SOURCE_DIR}/src/main-server.c")
  set_target_properties(
    wazuh-manager-authd PROPERTIES LINKER_LANGUAGE CXX RUNTIME_OUTPUT_DIRECTORY
                                                     ${SRC_FOLDER}/build/bin)
  target_link_libraries(wazuh-manager-authd PRIVATE authd_lib)
  wazuh_link_jemalloc(wazuh-manager-authd)

  wazuh_set_runtime_rpath(wazuh-manager-authd)
endif()

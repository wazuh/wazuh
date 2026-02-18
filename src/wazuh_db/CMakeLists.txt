cmake_minimum_required(VERSION 3.12.4)

project(wazuh-db C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/shared/include/
  ${SRC_FOLDER}/shared/os_net/
  ${SRC_FOLDER}/shared/os_regex/
  ${SRC_FOLDER}/shared/os_xml/
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
  ${SRC_FOLDER}/external/zlib/
  ${SRC_FOLDER}/config/include/
  ${SRC_FOLDER}/data_provider/include/
  ${SRC_FOLDER}/syscheckd/include/
  ${SRC_FOLDER}/wazuh_modules/include/
  ${SRC_FOLDER}/wazuh_modules/src/
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/
  ${SRC_FOLDER}/wazuh_modules/src/task_manager/
  ${SRC_FOLDER}/shared_modules/router/include/
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

add_definitions(-DARGV0="wazuh-manager-db")
add_definitions(-DGROUPGLOBAL="${WAZUH_RUNTIME_GROUP}")
add_definitions(-DUSER="${WAZUH_RUNTIME_USER}")

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})

# --- Embed SQL schemas as C string constants ---
file(GLOB SQL_SCHEMAS "${CMAKE_CURRENT_SOURCE_DIR}/schemas/*.sql")
set(GENERATED_SQL_SOURCES "")

foreach(sql_file ${SQL_SCHEMAS})
  get_filename_component(sql_name ${sql_file} NAME_WE)
  set(gen_c "${CMAKE_CURRENT_BINARY_DIR}/${sql_name}.c")
  add_custom_command(
    OUTPUT ${gen_c}
    COMMAND
      ${CMAKE_COMMAND} -DSQL_FILE=${sql_file} -DOUT_FILE=${gen_c}
      -DVAR_NAME=${sql_name}_sql -P ${CMAKE_CURRENT_SOURCE_DIR}/embed_sql.cmake
    DEPENDS ${sql_file} ${CMAKE_CURRENT_SOURCE_DIR}/embed_sql.cmake
    COMMENT "Embedding SQL schema ${sql_name}")
  list(APPEND GENERATED_SQL_SOURCES ${gen_c})
endforeach()

# Collect source files
file(GLOB WDB_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Build static library (without main.c) for unit tests
list(REMOVE_ITEM WDB_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
add_library(wdb_lib STATIC ${WDB_SRC} ${GENERATED_SQL_SOURCES})
set_target_properties(wdb_lib PROPERTIES LINKER_LANGUAGE C)

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(wdb_lib PRIVATE WAZUH_UNIT_TESTING)
  target_compile_options(wdb_lib PRIVATE -O0 -g)
endif()

target_link_libraries(wdb_lib PUBLIC wazuhext pthread router config
                                     wazuh_modulesd_lib wazuh)

if(UNIX)
  target_link_libraries(wdb_lib PUBLIC dl)
  if(NOT APPLE)
    target_link_libraries(wdb_lib PUBLIC rt)
  endif(NOT APPLE)
endif(UNIX)

# Only build Unix executable when not running unit tests (server-only, no
# Windows)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT UNIT_TEST)
  add_executable(wazuh-manager-db "${CMAKE_CURRENT_SOURCE_DIR}/src/main.c")
  set_target_properties(
    wazuh-manager-db PROPERTIES LINKER_LANGUAGE C RUNTIME_OUTPUT_DIRECTORY
                                                  ${SRC_FOLDER})
  target_link_libraries(wazuh-manager-db PRIVATE wdb_lib)

  if(APPLE)
    set_target_properties(
      wazuh-manager-db PROPERTIES BUILD_WITH_INSTALL_RPATH TRUE
                                  INSTALL_RPATH "@executable_path/../lib")
  else()
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -Wl,-rpath,$ORIGIN/../lib")
  endif()
endif()

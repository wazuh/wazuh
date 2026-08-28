cmake_minimum_required(VERSION 3.12.4)

project(manager_config)

# Manager-only module (Y19): loads etc/wazuh-manager.yml, validates it against the embedded
# JSON Schema (draft-04), fills defaults, applies cross-field semantics and exposes the
# effective document as JSON to C (manager_config_c.h) and C++ (manager_config.hpp) consumers.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

# Embed the schema at build time: the daemons never depend on an editable file.
# The same JSON is installed as $WAZUH_HOME/etc/wazuh-manager.schema.json for the Python framework.
set(MANAGER_CONFIG_SCHEMA_FILE ${CMAKE_CURRENT_SOURCE_DIR}/schema/wazuh-manager.schema.json)
file(READ ${MANAGER_CONFIG_SCHEMA_FILE} MANAGER_CONFIG_SCHEMA_TEXT)
string(FIND "${MANAGER_CONFIG_SCHEMA_TEXT}" ")MCFGSCHEMA\"" _delimiter_clash)
if(NOT _delimiter_clash EQUAL -1)
  message(FATAL_ERROR "manager_config: the schema contains the raw-string delimiter")
endif()
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/embeddedSchema.hpp.in
               ${CMAKE_CURRENT_BINARY_DIR}/generated/embeddedSchema.hpp @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${MANAGER_CONFIG_SCHEMA_FILE})

add_library(manager_config STATIC
  src/manager_config.cpp
  src/manager_config_c.cpp
  src/yamlToJson.cpp
  src/schemaValidate.cpp
  src/defaults.cpp
  src/semantics.cpp)

target_include_directories(manager_config
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${CMAKE_CURRENT_BINARY_DIR}/generated
          ${SRC_FOLDER}/external/yaml-cpp/include)

# yaml-cpp: imported target from src/external (server only); rapidjson: header-only INTERFACE target.
target_link_libraries(manager_config PRIVATE ext_yamlcpp ext_rapidjson)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(manager_config)
  add_subdirectory(tests)
endif()

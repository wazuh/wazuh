# SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
cmake_minimum_required(VERSION 3.12.4)

project(keystore)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(ORIGINAL_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if(NOT DEFINED SHARED_MODULES)
  get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

include_directories(include)
include_directories(src)
include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/common)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)
link_directories(${SRC_FOLDER}/external/rocksdb/build)

# keyStore.cpp is compiled once. keystore_core holds only its objects, for a binary that defines
# Log::GLOBAL_LOG_FUNCTION itself (the engine: its own definition, assigned in main.cpp, is the one keystore logs
# through). keystore holds the same objects plus that definition (keystoreLog.cpp) in one archive: the linker rescans
# the members of an archive, so the definition is always found, whatever the link order.
add_library(keystore_objects OBJECT src/keyStore.cpp)

add_library(keystore_core STATIC $<TARGET_OBJECTS:keystore_objects>)
target_link_libraries(keystore_core PRIVATE rocksdb wazuhext)

add_library(keystore STATIC $<TARGET_OBJECTS:keystore_objects> src/keystoreLog.cpp)
target_link_libraries(keystore PRIVATE rocksdb wazuhext)

if(NOT UNIT_TEST)
  add_executable(wazuh-manager-keystore src/main.cpp)

  target_link_libraries(wazuh-manager-keystore keystore)

  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_POSITION_INDEPENDENT_CODE)
    set_property(TARGET wazuh-manager-keystore APPEND_STRING PROPERTY LINK_FLAGS " -pie")
  endif()

  set_target_properties(
    wazuh-manager-keystore PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                      BUILD_RPATH "$ORIGIN/../lib")
endif(NOT UNIT_TEST)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${ORIGINAL_RUNTIME_OUTPUT_DIRECTORY})

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(keystore_objects)
  add_coverage_libraries(keystore_core)
  add_coverage_libraries(keystore)
  add_subdirectory(tests)
endif()

add_subdirectory(testtool)

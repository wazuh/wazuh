cmake_minimum_required(VERSION 3.12.4)

project(keystore)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-fPIC")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(ORIGINAL_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER})

file(GLOB KEYSTORE_SRC "src/keyStore.cpp")

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
link_directories(${SRC_FOLDER}/external/rocksdb/build)

add_library(keystore STATIC ${KEYSTORE_SRC})

target_link_libraries(keystore PRIVATE rocksdb wazuhext)

if(NOT UNIT_TEST)
  add_executable(wazuh-keystore src/main.cpp)

  target_link_libraries(wazuh-keystore keystore)

  set_target_properties(wazuh-keystore PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                  BUILD_RPATH "$ORIGIN/../lib")
endif(NOT UNIT_TEST)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${ORIGINAL_RUNTIME_OUTPUT_DIRECTORY})

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(keystore)
  add_subdirectory(tests)
endif()

add_subdirectory(testtool)

cmake_minimum_required(VERSION 3.12.4)

project(wazuh-keystore-testtool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if(NOT SHARED_MODULES)
  get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/rocksdb/include)
include_directories(${SRC_FOLDER}/external/openssl/include)
include_directories(${SRC_FOLDER}/external/cJSON)
include_directories(${SHARED_MODULES}/utils)
include_directories(${SHARED_MODULES}/common)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/rocksdb/build)

add_executable(${PROJECT_NAME} main.cpp)

set_target_properties(
  ${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                             "${CMAKE_BINARY_DIR}/bin")

target_link_libraries(${PROJECT_NAME} rocksdb wazuhext keystore)

cmake_minimum_required(VERSION 3.12.4)

project(container_connector CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "container_connector module is Linux-only; skipping on ${CMAKE_SYSTEM_NAME}.")
  return()
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(container_connector_impl)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/shared/include
  ${SRC_FOLDER}/external/cJSON
  ${SRC_FOLDER}/wazuh_modules
  ${SRC_FOLDER}/wazuh_modules/src
)

file(GLOB CONTAINER_CONNECTOR_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(container_connector SHARED ${CONTAINER_CONNECTOR_SRC})

# Make the C API header reachable from every target that links against this lib
# (e.g. wazuh_modulesd_lib needs <container_connector.h> from the glue source).
target_include_directories(container_connector PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(container_connector PRIVATE CONTAINER_CONNECTOR_IMPL)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(container_connector)
endif()

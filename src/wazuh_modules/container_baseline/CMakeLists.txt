cmake_minimum_required(VERSION 3.12.4)

project(container_baseline CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "container_baseline module is Linux-only; skipping on ${CMAKE_SYSTEM_NAME}.")
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

add_subdirectory(container_baseline_impl)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/shared/include
  ${SRC_FOLDER}/wazuh_modules/container_connector/include
)

file(GLOB CONTAINER_BASELINE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(container_baseline SHARED ${CONTAINER_BASELINE_SRC})

# Make the C API header reachable from every target that links against this lib
# (e.g. syscheckd needs <container_baseline.h> from container_baseline_fim.c).
target_include_directories(container_baseline PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(container_baseline PRIVATE CONTAINER_BASELINE_IMPL)

string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(container_baseline)
endif()

cmake_minimum_required(VERSION 3.12.4)

project(container_attribution CXX)

# cgroup_id -> container_id attribution for the consumers of the eBPF engine:
# the cgroup map and the planner that keeps it in step with container_instances.
# Linux only, like the engine and container_instances' client.

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "container_attribution is Linux-only; skipping on ${CMAKE_SYSTEM_NAME}.")
  return()
endif()

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_library(container_attribution STATIC src/container_list_refresh.cpp)

target_include_directories(container_attribution PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/shared_modules/container_instances_client/include
  ${SRC_FOLDER}/shared_modules/common
  ${SRC_FOLDER}/external/nlohmann
)

target_compile_options(container_attribution PRIVATE
  -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2
)

# Linked into shared libraries (syscheckd's fimebpf).
set_target_properties(container_attribution PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(UNIT_TEST)
  target_compile_options(container_attribution PRIVATE --coverage)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(container_attribution PRIVATE -fprofile-arcs)
  else()
    target_link_libraries(container_attribution PRIVATE gcov)
  endif()
  add_subdirectory(tests)
endif(UNIT_TEST)

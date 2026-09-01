cmake_minimum_required(VERSION 3.12.4)
project(ebpf)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wformat=2 -fPIC"
)

# Output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Shared eBPF library: each module links it and owns its own BPF object
add_library(
  ebpf SHARED
  src/ebpf_loader.cpp
)

target_include_directories(
  ebpf
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${SRC_FOLDER}/external/libbpf-bootstrap/build/libbpf
    ${SRC_FOLDER}/external/libbpf-bootstrap/build/libbpf/include
    ${SRC_FOLDER}/shared/include
    ${SRC_FOLDER}/shared_modules/utils
)

target_link_libraries(
  ebpf
  PRIVATE
    pthread
    dl
    wazuh
)

if(EXISTS ${SRC_FOLDER}/external/libbpf-bootstrap/build/libbpf/libbpf.a)
  target_link_libraries(ebpf PRIVATE ${SRC_FOLDER}/external/libbpf-bootstrap/build/libbpf/libbpf.a -lelf -lz)
endif()

# Copy precompiled modern.bpf.o to lib directory if available
set(PRECOMPILED_BPF_OBJ ${SRC_FOLDER}/external/libbpf-bootstrap/build/modern.bpf.o)
if(EXISTS ${PRECOMPILED_BPF_OBJ})
  add_custom_command(
    TARGET ebpf POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different ${PRECOMPILED_BPF_OBJ} ${CMAKE_BINARY_DIR}/lib/modern.bpf.o
    COMMENT "Copying precompiled modern.bpf.o to lib directory"
  )
endif()

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(ebpf PRIVATE --coverage)
    target_link_libraries(ebpf PRIVATE -fprofile-arcs)
  else()
    target_compile_options(ebpf PRIVATE --coverage)
    target_link_libraries(ebpf PRIVATE gcov)
  endif()
  add_subdirectory(tests)
endif()

cmake_minimum_required(VERSION 3.10)

# Set the project name
project(fimebpf)

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/libbpf-bootstrap/build/)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src/db/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/ebpf/include/)

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_library(fimebpf SHARED src/ebpf_whodata.cpp)

# Set additional compile flags for the loader (if needed)
target_compile_options(fimebpf PRIVATE -Wall -Wextra)

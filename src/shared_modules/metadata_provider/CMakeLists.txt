cmake_minimum_required(VERSION 3.12.4)
project(metadata_provider)

# Default to Release if not specified
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Compiler flags
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -fPIC -pthread"
)
set(CMAKE_CXX_FLAGS_DEBUG "-g")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif()

# Address/UB sanitizer (optional)
if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif()

# Set output directories
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Build the metadata_provider library
add_library(metadata_provider SHARED
  src/metadata_provider.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../../${RESOURCE_OBJ}
)

target_include_directories(metadata_provider
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    metadata_provider PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias -Wl,--output-def,libmetadata_provider.def")

  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
  endif(NOT DLLTOOL)

  add_custom_command(TARGET metadata_provider POST_BUILD
    COMMAND "${DLLTOOL}" -D "libmetadata_provider.dll" --def "libmetadata_provider.def" --output-delaylib "libmetadata_provider.lib"
    COMMAND cp "libmetadata_provider.lib" "${CMAKE_BINARY_DIR}/bin/libmetadata_provider.lib"
    COMMENT "Creating delayed load library for metadata_provider.")
elseif(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  enable_testing()
  add_subdirectory(tests)

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(metadata_provider PRIVATE -fprofile-arcs -ftest-coverage)
    target_link_libraries(metadata_provider PRIVATE -fprofile-arcs)
  else()
    target_compile_options(metadata_provider PRIVATE --coverage)
    target_link_libraries(metadata_provider PRIVATE --coverage)
  endif()
endif()

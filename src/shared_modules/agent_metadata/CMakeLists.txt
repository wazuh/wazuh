cmake_minimum_required(VERSION 3.12.4)

project(agent_metadata)

enable_testing()

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(NOT SRC_FOLDER STREQUAL "/")
  get_filename_component(SRC_FOLDER ${SRC_FOLDER} ABSOLUTE)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Address/UB sanitizer (optional)
if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/include/)

add_library(agent_metadata SHARED
  src/metadata_provider.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../../${RESOURCE_OBJ}
)

set_target_properties(agent_metadata PROPERTIES
  OUTPUT_NAME agent_metadata
  ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
  RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

target_include_directories(agent_metadata PUBLIC
  ${CMAKE_SOURCE_DIR}/include
)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    agent_metadata PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias -Wl,--output-def,libagent_metadata.def")

  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
  endif(NOT DLLTOOL)

  add_custom_command(TARGET agent_metadata POST_BUILD
    COMMAND "${DLLTOOL}" -D "libagent_metadata.dll" --def "libagent_metadata.def" --output-delaylib "libagent_metadata.lib"
    COMMAND cp "libagent_metadata.lib" "${CMAKE_BINARY_DIR}/bin/libagent_metadata.lib"
    COMMENT "Creating delayed load library for agent_metadata.")
elseif(UNIX AND NOT APPLE)
  target_link_libraries(agent_metadata PRIVATE pthread)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  add_subdirectory(tests)

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(agent_metadata PRIVATE -fprofile-arcs -ftest-coverage)
    target_link_libraries(agent_metadata PRIVATE -fprofile-arcs)
  else()
    target_compile_options(agent_metadata PRIVATE --coverage)
    target_link_libraries(agent_metadata PRIVATE --coverage)
  endif()
endif()

cmake_minimum_required(VERSION 3.12.4)

project(sca)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
  add_definitions(-DPROMISE_TYPE=PromiseType::SLEEP)
else()
  add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)
endif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14 -pthread"
)

set(CMAKE_CXX_FLAGS_DEBUG "-g")
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

include_directories(${SRC_FOLDER}/headers)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${CMAKE_SOURCE_DIR}/include)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_WIN32_WINNT=0x600 -DWIN_EXPORT)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

file(GLOB SCA_SRC "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_library(sca SHARED ${SCA_SRC} ${SRC_FOLDER}/${RESOURCE_OBJ})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    sca
    PROPERTIES PREFIX ""
               SUFFIX ".dll"
               LINK_FLAGS "-Wl,--add-stdcall-alias"
               POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
               # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(sca -fprofile-arcs)
  else()
    target_link_libraries(sca gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
else()
  if(FSANITIZE)
    target_link_libraries(sca gcov)
  endif(FSANITIZE)
endif(UNIT_TEST)

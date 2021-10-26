cmake_minimum_required(VERSION 3.12.4)

project(fimdb)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

if(SOLARIS)
  add_definitions(-DSOLARIS=ON)
endif(SOLARIS)

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

set(LIB_DIR ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

include_directories(${SRC_FOLDER}/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/bzip2/)
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/data_provider/include/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${SRC_FOLDER}/syscheckd)
include_directories(${CMAKE_SOURCE_DIR}/include)

link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)
link_directories(${SRC_FOLDER}/data_provider/build/lib)
link_directories(${SRC_FOLDER})

link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/bzip2/)
link_directories(${SRC_FOLDER}/external/openssl/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_WIN32_WINNT=0x600 -DWIN_EXPORT)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_library(fimdb STATIC ${CMAKE_SOURCE_DIR}/src/db.cpp
                         ${CMAKE_SOURCE_DIR}/src/file.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    fimdb PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias -static-libstdc++")
  target_sources(fimdb PUBLIC ${CMAKE_SOURCE_DIR}/src/registry.cpp)
elseif(UNIX AND NOT APPLE)
  set_target_properties(fimdb PROPERTIES LINK_FLAGS
                                         "-static-libgcc -static-libstdc++")
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
  target_link_libraries(fimdb dbsync rsync wazuhext)
else()
  string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR
                 "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
  string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR
                 "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
  target_link_libraries(
    fimdb
    dbsync
    rsync
    wazuhext
    -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR}
  )
endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(fimdb -fprofile-arcs)
  else()
    target_link_libraries(fimdb gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
else()
  if(FSANITIZE)
    target_link_libraries(fimdb gcov)
  endif(FSANITIZE)
endif(UNIT_TEST)

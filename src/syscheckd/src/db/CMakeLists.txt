cmake_minimum_required(VERSION 3.12.4)

project(fimdb)

enable_testing()

include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/syscheckd)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src)

file(GLOB DB_SRC
     ${CMAKE_SOURCE_DIR}/src/db/src/db.cpp
     ${CMAKE_SOURCE_DIR}/src/db/src/file.cpp
     ${CMAKE_SOURCE_DIR}/src/db/src/fimDB.cpp
     ${CMAKE_SOURCE_DIR}/src/db/src/dbFileItem.cpp
     ${CMAKE_SOURCE_DIR}/src/db/src/dbRegistryKey.cpp
     ${CMAKE_SOURCE_DIR}/src/db/src/dbRegistryValue.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "SunOS")
  add_definitions(-DSOLARIS=ON)
endif(CMAKE_SYSTEM_NAME STREQUAL "SunOS")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(fimdb STATIC ${DB_SRC}
                           # ${CMAKE_SOURCE_DIR}/src/db/src/registry.cpp
                           )
else()
  add_library(fimdb SHARED ${DB_SRC})
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")


if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    fimdb PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias -static-libstdc++")
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
  add_subdirectory(testtool)
  if(FSANITIZE)
    target_link_libraries(fimdb gcov)
  endif(FSANITIZE)
endif(UNIT_TEST)

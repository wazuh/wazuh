cmake_minimum_required(VERSION 3.12.4)

project(fimdb)

enable_testing()

include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/syscheckd)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src)

if(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
  link_directories(${INSTALL_PREFIX}/lib)
  add_definitions(-DPROMISE_TYPE=PromiseType::SLEEP)
else()
  add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)
endif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")

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
  add_definitions(-DOS_TYPE=OSType::WINDOWS)
  add_library(fimdb SHARED ${DB_SRC}
                           ${CMAKE_SOURCE_DIR}/src/db/src/registry.cpp
                           ${CMAKE_SOURCE_DIR}/src/db/src/fimDBSpecializationWindows.cpp
                           ${SRC_FOLDER}/${RESOURCE_OBJ}
                           )
elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
  add_definitions(-DOS_TYPE=OSType::OTHERS)
  add_library(fimdb SHARED ${DB_SRC})
else()
  add_definitions(-DOS_TYPE=OSType::OTHERS)
  add_library(fimdb SHARED ${DB_SRC})
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")


if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    fimdb PROPERTIES LINK_FLAGS "-Wl,--add-stdcall-alias -Wl,--output-def,libfimdb.def")
elseif(UNIX AND NOT APPLE)
  if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR
                 "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR
                 "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "HP-UX")
    # Do nothing for HP-UX
  else()
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif(CMAKE_SYSTEM_NAME STREQUAL "AIX")


endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
  target_link_libraries(fimdb dbsync rsync wazuhext)
else()
  target_link_libraries(
    fimdb
    dbsync
    rsync
    wazuhext
    -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR}
  )
endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  find_program(DLLTOOL i686-w64-mingw32-dlltool)
if(NOT DLLTOOL)
  message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
endif(NOT DLLTOOL)

add_custom_command(TARGET fimdb POST_BUILD
  COMMAND "${DLLTOOL}" -D "libfimdb.dll" --def "libfimdb.def" --output-delaylib "libfimdb.lib"
  COMMAND cp "libfimdb.lib" "${CMAKE_BINARY_DIR}/bin/libfimdb.lib"
  COMMENT "Creating delayed load library for fimdb.")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

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

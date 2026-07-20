cmake_minimum_required(VERSION 3.12.4)

project(fimdb)

include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/external/libpcre2/include/)
include_directories(${SRC_FOLDER}/shared/os_regex/)
include_directories(${SRC_FOLDER}/syscheckd)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

file(
  GLOB
  DB_SRC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/db.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/file.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/fimDB.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/dbFileItem.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/dbRegistryKey.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/src/dbRegistryValue.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DOS_TYPE=OSType::WINDOWS)
  add_library(
    fimdb SHARED
    ${DB_SRC} ${CMAKE_CURRENT_SOURCE_DIR}/src/registry.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/fimDBSpecializationWindows.cpp
    ${RESOURCE_OBJ_DLL})
else()
  add_definitions(-DOS_TYPE=OSType::OTHERS)
  add_library(fimdb SHARED ${DB_SRC})
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    fimdb
    PROPERTIES LINK_FLAGS
               "-Wl,--add-stdcall-alias -Wl,--output-def,libfimdb.def"
               RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
elseif(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(fimdb PRIVATE dbsync wazuhext)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
  endif(NOT DLLTOOL)

  add_custom_command(
    TARGET fimdb
    POST_BUILD
    COMMAND "${DLLTOOL}" -D "libfimdb.dll" --def "libfimdb.def"
            --output-delaylib "libfimdb.lib"
    COMMAND cp "libfimdb.lib" "${CMAKE_BINARY_DIR}/bin/libfimdb.lib"
    COMMENT "Creating delayed load library for fimdb.")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(fimdb)

  # Add coverage flags globally for all test executables (including those that
  # compile sources directly)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(--coverage)
    add_link_options(-fprofile-arcs)
  else()
    add_compile_options(--coverage)
    add_link_options(--coverage)
  endif()

  add_subdirectory(tests)
endif(UNIT_TEST)

add_subdirectory(testtool)

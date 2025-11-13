cmake_minimum_required(VERSION 3.12.4)

project(fim_recovery)

enable_testing()

include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/shared_modules/utils)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include/)
include_directories(${SRC_FOLDER}/syscheckd)
include_directories(${SRC_FOLDER}/syscheckd/src/db/include/)
include_directories(${SRC_FOLDER}/syscheckd/src/db/src)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

file(GLOB FIM_RECOVERY_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_library(fim_recovery SHARED ${FIM_RECOVERY_SRC} ${SRC_FOLDER}/${RESOURCE_OBJ})
else()
  add_library(fim_recovery SHARED ${FIM_RECOVERY_SRC})
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(fim_recovery wazuhext agent_sync_protocol dbsync fimdb)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(fim_recovery PROPERTIES
    LINK_FLAGS "-Wl,--add-stdcall-alias -Wl,--output-def,libfim_recovery.def"
    POSITION_INDEPENDENT_CODE 0
  )
  # Link against fimdb using the import library (.dll.a) directly
  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "DLL tool for delayed load libraries not found.")
  endif(NOT DLLTOOL)

  add_custom_command(TARGET fim_recovery POST_BUILD
    COMMAND "${DLLTOOL}" -D "libfim_recovery.dll" --def "libfim_recovery.def" --output-delaylib "libfim_recovery.lib"
    COMMAND cp "libfim_recovery.lib" "${CMAKE_BINARY_DIR}/bin/libfim_recovery.lib"
    COMMENT "Creating delayed load library for fim_recovery.")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

if(UNIT_TEST)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(fim_recovery -fprofile-arcs)
  else()
    target_link_libraries(fim_recovery gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_subdirectory(tests)
else()
  if(FSANITIZE)
    target_link_libraries(fim_recovery gcov)
  endif(FSANITIZE)
endif(UNIT_TEST)

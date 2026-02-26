cmake_minimum_required(VERSION 3.12.4)

# Force ranlib and windres for scan-build cross-compilation compatibility Must
# be set BEFORE project() command to take effect
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Set the correct cross-compilation tools
  set(CMAKE_RANLIB
      "i686-w64-mingw32-ranlib"
      CACHE FILEPATH "Ranlib for Windows cross-compilation" FORCE)
  set(CMAKE_RC_COMPILER
      "i686-w64-mingw32-windres"
      CACHE FILEPATH "Resource compiler for Windows cross-compilation" FORCE)
  set(CMAKE_C_ARCHIVE_FINISH "<CMAKE_RANLIB> <TARGET>")
  set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> <TARGET>")
endif()

project(Wazuh)

enable_testing()

if(NOT CMAKE_BUILD_TYPE)
  if(CMAKE_SYMBOLS_IN_RELEASE MATCHES "ON")
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
  else()
    set(CMAKE_BUILD_TYPE Release)
  endif()
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Coverity static analysis compatibility
if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

# Compiler flags for Debug and Release builds
if(NOT FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3")
else()
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -s")
endif()

# Sanitizer flags (override DEBUG flags when enabled)
if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif(FSANITIZE)

# Function to link coverage libraries for unit tests Uses plain signature for
# compatibility with existing plain signature usage
function(add_coverage_libraries target_name)
  if(UNIT_TEST)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      target_compile_options(${target_name} PUBLIC --coverage)
      target_link_libraries(${target_name} PUBLIC -fprofile-arcs)
    else()
      target_compile_options(${target_name} PUBLIC --coverage)
      target_link_libraries(${target_name} PUBLIC gcov)
    endif()
  endif()
endfunction()

# SRC_FOLDER should point to the src/ directory Sub-modules will try to redefine
# it, so we set a guard variable
set(SRC_FOLDER ${CMAKE_SOURCE_DIR})
set(WAZUH_MAIN_PROJECT
    ON
    CACHE BOOL "Main Wazuh CMake project" FORCE)

# Define CLIENT for agent builds
if("${TARGET}" STREQUAL "winagent" OR "${TARGET}" STREQUAL "agent")
  add_definitions(-DCLIENT)
endif()

# Keep Make-based Windows semantics for external headers that otherwise declare
# symbols as dllimport. We link these through delay import stubs.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DPCRE2_EXP_DECL= -DBUILDING_LIBCURL=)

  # Add system include paths for scan-build cross-compilation compatibility
  # These paths are needed when using clang static analyzer wrappers with mingw
  set(MINGW_SYSTEM_INCLUDES
      "-isystem/usr/lib/gcc/i686-w64-mingw32/13-posix/include/c++"
      "-isystem/usr/lib/gcc/i686-w64-mingw32/13-posix/include/c++/i686-w64-mingw32"
      "-isystem/usr/lib/gcc/i686-w64-mingw32/13-posix/include/c++/backward"
      "-isystem/usr/lib/gcc/i686-w64-mingw32/13-posix/include"
      "-isystem/usr/lib/gcc/i686-w64-mingw32/13-posix/include-fixed"
      "-isystem/usr/lib/gcc/i686-w64-mingw32/13-posix/../../../../i686-w64-mingw32/include"
  )

  # Add flags directly to compiler to work around scan-build issues with
  # response files
  add_compile_options(${MINGW_SYSTEM_INCLUDES})

  # Disable response files for scan-build compatibility
  set(CMAKE_CXX_USE_RESPONSE_FILE_FOR_INCLUDES OFF)
  set(CMAKE_C_USE_RESPONSE_FILE_FOR_INCLUDES OFF)
endif()
# Set Wine as crosscompiling emulator for Windows unit tests
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND UNIT_TEST)
  find_program(WINE "wine")
  if(NOT WINE)
    message(WARNING "Wine is required to run Windows tests on Linux")
  endif()
  set(CMAKE_CROSSCOMPILING_EMULATOR wine)
endif()

# Read the VERSION JSON file
file(READ "${SRC_FOLDER}/../VERSION.json" VERSION_JSON)

# Extract "version"
string(REGEX MATCH "\"version\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(VERSION_FILE "v${CMAKE_MATCH_1}") # <-- Add "v" prefix since old VERSION
                                      # file had it

# Extract "stage" as revision
string(REGEX MATCH "\"stage\"[ \t]*:[ \t]*\"([^\"]+)\"" _ ${VERSION_JSON})
set(REVISION_FILE "${CMAKE_MATCH_1}")

# Define preprocessor macros
add_definitions(-DVERSION="${VERSION_FILE}")
add_definitions(-DREVISION="${REVISION_FILE}")

# If REVISION OR FILE is empty fail
if("${REVISION_FILE}" STREQUAL "")
  message(FATAL_ERROR "REVISION file is empty")
endif("${REVISION_FILE}" STREQUAL "")

if("${VERSION_FILE}" STREQUAL "")
  message(FATAL_ERROR "VERSION file is empty")
endif("${VERSION_FILE}" STREQUAL "")

message("==============================================")
message("Wazuh version: ${VERSION_FILE}")
message("Wazuh revision: ${REVISION_FILE}")
message("==============================================")

set(BENCHMARK_ENABLE_TESTING "OFF")

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/build/lib)

# Wazuh headers
include_directories(${SRC_FOLDER}/shared/include)

# Shared modules includes
include_directories(${SRC_FOLDER}/shared_modules/agent_metadata/include)
include_directories(${SRC_FOLDER}/shared_modules/common)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/include)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include)
include_directories(${SRC_FOLDER}/shared_modules/http-request/include)
include_directories(${SRC_FOLDER}/shared_modules/indexer_connector/include)
include_directories(${SRC_FOLDER}/shared_modules/keystore/include)
include_directories(${SRC_FOLDER}/shared_modules/router/include)
include_directories(${SRC_FOLDER}/shared_modules/schema_validator/include)
include_directories(${SRC_FOLDER}/shared_modules/sync_protocol/include)
include_directories(${SRC_FOLDER}/shared_modules/utils)

# Windows version resource objects
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  enable_language(RC)

  # Version resource for DLLs (VFT_DLL)
  add_library(version_rc_dll OBJECT ${SRC_FOLDER}/win32/version.rc)
  target_compile_definitions(version_rc_dll PRIVATE VER_TYPE=VFT_DLL)

  # Version resource for executables (VFT_APP)
  add_library(version_rc_app OBJECT ${SRC_FOLDER}/win32/version.rc)
  target_compile_definitions(version_rc_app PRIVATE VER_TYPE=VFT_APP)

  set(RESOURCE_OBJ_DLL $<TARGET_OBJECTS:version_rc_dll>)
  set(RESOURCE_OBJ_APP $<TARGET_OBJECTS:version_rc_app>)

  find_program(MINGW_AR i686-w64-mingw32-ar REQUIRED)
  find_library(
    WIN_PTHREAD_STATIC_LIB
    NAMES winpthread
    PATHS /usr/i686-w64-mingw32/lib /usr/i686-w64-mingw32/sys-root/mingw/lib
          REQUIRED)
  find_file(
    WIN_PTHREAD_DLL
    NAMES libwinpthread-1.dll
    PATHS /usr/i686-w64-mingw32/lib /usr/i686-w64-mingw32/sys-root/mingw/bin
          REQUIRED)

  set(PATCHED_PTHREAD_LIB ${SRC_FOLDER}/build/lib/libwinpthreadpatched.a)
  set(WIN_PTHREAD_DLL_COPY ${SRC_FOLDER}/build/lib/libwinpthread-1.dll)
  add_custom_command(
    OUTPUT ${PATCHED_PTHREAD_LIB}
    COMMAND ${CMAKE_COMMAND} -E copy ${WIN_PTHREAD_STATIC_LIB}
            ${PATCHED_PTHREAD_LIB}
    COMMAND ${MINGW_AR} d ${PATCHED_PTHREAD_LIB} version.o
    DEPENDS ${WIN_PTHREAD_STATIC_LIB}
    COMMENT "Creating patched pthread library")
  add_custom_command(
    OUTPUT ${WIN_PTHREAD_DLL_COPY}
    COMMAND ${CMAKE_COMMAND} -E copy ${WIN_PTHREAD_DLL} ${WIN_PTHREAD_DLL_COPY}
    DEPENDS ${WIN_PTHREAD_DLL}
    COMMENT "Copying pthread DLL")
  add_custom_target(winpthreadpatched ALL DEPENDS ${PATCHED_PTHREAD_LIB}
                                                  ${WIN_PTHREAD_DLL_COPY})

  # Common Windows libraries that all Windows executables need
  set(WAZUH_WINDOWS_LIBS
      ${SRC_FOLDER}/build/lib/libwazuhext.lib ${PATCHED_PTHREAD_LIB} wintrust
      psapi crypt32 shlwapi
      CACHE INTERNAL "Common Windows libraries for all executables")
endif()

# Helper variables
set(IS_AGENT FALSE)
if("${TARGET}" STREQUAL "winagent" OR "${TARGET}" STREQUAL "agent")
  set(IS_AGENT TRUE)
endif()

# External dependencies
add_subdirectory(external)

# Common modules (all targets)
add_subdirectory(config)
add_subdirectory(shared)
add_subdirectory(shared_modules/file_helper)
set(CURL_DEP wazuhext)
add_subdirectory(shared_modules/http-request)
add_subdirectory(shared_modules/schema_validator)
add_subdirectory(shared_modules/utils)
add_subdirectory(wazuh_modules)

# Agent-only modules
if(IS_AGENT)
  add_subdirectory(active-response)
  add_subdirectory(addagent)
  add_subdirectory(client-agent)
  add_subdirectory(data_provider)
  add_subdirectory(logcollector)
  add_subdirectory(os_execd)
  add_subdirectory(rootcheck)
  add_subdirectory(shared_modules/agent_metadata)
  add_subdirectory(shared_modules/dbsync)
  add_subdirectory(shared_modules/sync_protocol)
  add_subdirectory(syscheckd)
  # Windows agent executables and resources
  if("${TARGET}" STREQUAL "winagent")
    add_subdirectory(win32)
  endif()
endif()

# Server-only modules
if(NOT IS_AGENT)
  add_subdirectory(engine)
  add_subdirectory(monitord)
  add_subdirectory(os_auth)
  add_subdirectory(remoted)
  add_subdirectory(shared_modules/content_manager)
  add_subdirectory(shared_modules/indexer_connector)
  add_subdirectory(shared_modules/keystore)
  add_subdirectory(shared_modules/router)
  add_subdirectory(util)
  add_subdirectory(wazuh_db)
endif()

# Create flatbuffers alias if the real target wasn't created by subdirectories
if(NOT TARGET flatbuffers)
  add_library(flatbuffers ALIAS ext_flatbuffers)
endif()

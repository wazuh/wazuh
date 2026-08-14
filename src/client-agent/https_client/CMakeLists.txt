cmake_minimum_required(VERSION 3.12.4)

project(https_client CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Colocate the .so next to the other agent shared libs (e.g.
# libagent_sync_protocol.so) so agentd's runtime rpath ($ORIGIN/../lib)
# resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB_RECURSE HTTPS_CLIENT_SRC "src/*.cpp")

add_library(https_client SHARED ${HTTPS_CLIENT_SRC} ${RESOURCE_OBJ_DLL})

target_compile_options(
  https_client PRIVATE -Wall -Wextra -Wshadow -Wnon-virtual-dtor
                       -Woverloaded-virtual -Wunused -Wcast-align -fPIC)

target_include_directories(
  https_client
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${SRC_FOLDER} # external/nlohmann/json.hpp (repo-style include)
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/external/cJSON # cJSON.h (pulled by commonDefs.h)
          ${SRC_FOLDER}/external/curl/include
          ${SRC_FOLDER}/external/openssl/include)

# wazuhext carries the vendored libcurl + OpenSSL symbols for agent targets.
# ext_zstd: request-body compression, same target remoted_module
# already links for the manager-side decode (#38129).
target_link_libraries(https_client PRIVATE wazuhext pthread ext_zstd)

set_target_properties(https_client PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                              BUILD_RPATH "$ORIGIN/../lib")

if(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif()

# winagent: emit the .def at link time and generate the MinGW delay-load
# import library the final win32 executables link against (the
# agent_sync_protocol recipe).
#
# --exclude-libs=libzstd.a: MinGW auto-exports every global symbol from a
# shared library by default (unlike ELF's convention), so without this,
# zstd's own public C API (ZSTD_isError, etc.) leaks into this DLL's export
# table/.def and gets its own delay-load thunk -- colliding with the real
# ZSTD_isError the test binary also links directly via ext_zstd (needed
# there to independently decompress and verify what this library produced).
# Confirmed empirically: omitting this flag produces a real
# "multiple definition of `ZSTD_isError'" link error building
# https_client_unit_test.exe.
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set_target_properties(
    https_client PROPERTIES LINK_FLAGS
                            "-Wl,--add-stdcall-alias -Wl,--exclude-libs,libzstd.a -Wl,--output-def,libhttps_client.def")

  find_program(DLLTOOL i686-w64-mingw32-dlltool)
  if(NOT DLLTOOL)
    message(FATAL_ERROR "i686-w64-mingw32-dlltool not found, needed for libhttps_client.lib")
  endif()

  add_custom_command(
    TARGET https_client
    POST_BUILD
    COMMAND "${DLLTOOL}" -D "libhttps_client.dll" --def "libhttps_client.def"
            --output-delaylib "libhttps_client.lib"
    COMMAND cp "libhttps_client.lib" "${CMAKE_BINARY_DIR}/bin/libhttps_client.lib"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating libhttps_client.lib import library")
endif()

# Optional ThreadSanitizer build for the concurrency workload (LifecycleChurn).
option(HTTPS_CLIENT_TSAN "Build https_client and its tests with ThreadSanitizer" OFF)
if(HTTPS_CLIENT_TSAN)
  target_compile_options(https_client PRIVATE -fsanitize=thread -g)
  target_link_options(https_client PRIVATE -fsanitize=thread)
endif()

if(UNIT_TEST)
  # add_coverage_libraries comes from the top-level src/CMakeLists.txt; guard
  # it so the module also configures standalone (cmake -S . -DSRC_FOLDER=...).
  if(COMMAND add_coverage_libraries)
    add_coverage_libraries(https_client)
  endif()
  enable_testing()
  add_subdirectory(tests)
endif()

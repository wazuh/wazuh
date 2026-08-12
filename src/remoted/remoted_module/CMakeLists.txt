cmake_minimum_required(VERSION 3.12.4)

project(remoted_module CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Colocate the .so next to the other manager shared libs
# so remoted's runtime rpath ($ORIGIN/../lib) resolves it.
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

file(GLOB_RECURSE REMOTED_MODULE_SRC "src/*.cpp")

add_library(remoted_module SHARED ${REMOTED_MODULE_SRC})

target_include_directories(
  remoted_module
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  # src/ is on the path so submodules resolve by prefix: "auth/...", "endpoints/...", "http_server/...".
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
          ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, singleton.hpp
          ${SRC_FOLDER}/shared_modules/common # commonDefs.h
          ${SRC_FOLDER}/external/cJSON # cJSON.h (pulled by commonDefs.h)
          ${SRC_FOLDER}/external/cpp-httplib # httplib.h (for UDS HTTP client)
          ${SRC_FOLDER}/external/nlohmann) # nlohmann/json.hpp

# ext_restinio pulls in ssl/crypto transitively (cmac.cpp's EVP_MAC), so no explicit OpenSSL link
# is needed here. ext_rapidjson: header-only, used to parse the /stateless payload's H line.
# ext_zstd: zstdDecoder.cpp, for Content-Encoding: zstd request bodies.
target_link_libraries(remoted_module PRIVATE pthread ext_restinio ext_rapidjson ext_zstd)

set_target_properties(remoted_module PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_subdirectory(test)
endif()

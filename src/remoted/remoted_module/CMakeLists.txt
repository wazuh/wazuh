cmake_minimum_required(VERSION 3.12.4)

project(remoted_module CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Colocate the .so next to the other manager shared libs (e.g. librouter.so)
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
          ${SRC_FOLDER}/external/openssl/include) # cmac.cpp (EVP_MAC)

find_library(
  OPENSSL_CRYPTO_LIB crypto
  HINTS ${SRC_FOLDER}/external/openssl
  NO_DEFAULT_PATH)

if(NOT OPENSSL_CRYPTO_LIB)
  set(OPENSSL_CRYPTO_LIB crypto)
  message(STATUS "OpenSSL crypto library not found, using target name")
endif()

# restinio::restinio: our HTTPS transport (also pulls ssl/crypto transitively).
# OPENSSL_CRYPTO_LIB: kept explicit for cmac.cpp's EVP_MAC (auth middleware).
target_link_libraries(
  remoted_module
  PRIVATE
    pthread
    restinio::restinio
    ${OPENSSL_CRYPTO_LIB}
)

set_target_properties(remoted_module PROPERTIES BUILD_RPATH_USE_ORIGIN TRUE
                                                BUILD_RPATH "$ORIGIN/../lib")

if(UNIT_TEST)
  enable_testing()
  add_subdirectory(test)
endif()

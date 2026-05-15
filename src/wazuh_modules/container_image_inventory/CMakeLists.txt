# container_image_inventory PoC
# Standalone module. The PoC binary links against the libarchive and sqlite3
# static libraries already shipped under src/external/. Build with:
#
#   cd src/wazuh_modules/container_image_inventory
#   cmake -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build -j
#
# Output binary: build/container-image-inventory-poc

cmake_minimum_required(VERSION 3.12)
project(container_image_inventory_poc CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# Resolve the wazuh src/ root. This module lives at src/wazuh_modules/<name>/.
get_filename_component(WZ_SRC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../" ABSOLUTE)

set(LIBARCHIVE_DIR "${WZ_SRC_ROOT}/external/libarchive")
set(SQLITE_DIR "${WZ_SRC_ROOT}/external/sqlite")
set(NLOHMANN_DIR "${WZ_SRC_ROOT}/external/nlohmann")
set(CURL_DIR "${WZ_SRC_ROOT}/external/curl")
set(OPENSSL_DIR "${WZ_SRC_ROOT}/external/openssl")

if(NOT EXISTS "${LIBARCHIVE_DIR}/.libs/libarchive.a")
  message(FATAL_ERROR "libarchive static lib not found at ${LIBARCHIVE_DIR}/.libs/libarchive.a. "
                      "Build it from src/ (e.g. via the standard wazuh build) before building this PoC.")
endif()
if(NOT EXISTS "${SQLITE_DIR}/libsqlite3.a")
  message(FATAL_ERROR "sqlite3 static lib not found at ${SQLITE_DIR}/libsqlite3.a. "
                      "Build the wazuh src/ tree to generate it.")
endif()
if(NOT EXISTS "${CURL_DIR}/include/curl/curl.h")
  message(FATAL_ERROR "libcurl headers not found at ${CURL_DIR}/include/curl/curl.h. "
                      "Build the wazuh src/ tree to make external/curl available.")
endif()
# Prefer the static library; fall back to the shared one.
set(CURL_LIB "${CURL_DIR}/lib/.libs/libcurl.a")
if(NOT EXISTS "${CURL_LIB}")
  set(CURL_LIB "${CURL_DIR}/lib/.libs/libcurl.so")
endif()
if(NOT EXISTS "${CURL_LIB}")
  message(FATAL_ERROR "libcurl library not found under ${CURL_DIR}/lib/.libs/")
endif()

add_library(container_image_inventory_lib STATIC
  src/containerImageInventory.cpp
  src/digestCache.cpp
  src/httpClient.cpp
  src/imageArchiveParser.cpp
  src/imageReference.cpp
  src/overlayFsResolver.cpp
  src/packageDbExtractor.cpp
  src/packageInventoryScanner.cpp
  src/registryClient.cpp
  src/remoteImageScanner.cpp
  src/tarUtils.cpp)

target_include_directories(container_image_inventory_lib PUBLIC
  include
  src
  ${LIBARCHIVE_DIR}/libarchive
  ${SQLITE_DIR}
  ${NLOHMANN_DIR}
  ${CURL_DIR}/include)

target_compile_options(container_image_inventory_lib PRIVATE
  -Wall -Wextra -Wshadow -Wnon-virtual-dtor -Wno-unused-parameter)

target_link_libraries(container_image_inventory_lib PUBLIC
  ${LIBARCHIVE_DIR}/.libs/libarchive.a
  ${SQLITE_DIR}/libsqlite3.a
  ${CURL_LIB}
  ${OPENSSL_DIR}/libssl.a
  ${OPENSSL_DIR}/libcrypto.a
  z
  pthread
  dl
  m
  stdc++fs)

add_subdirectory(testtool)

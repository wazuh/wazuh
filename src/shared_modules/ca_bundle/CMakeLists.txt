cmake_minimum_required(VERSION 3.12.4)

project(ca_bundle CXX)

# Manager-only library (C9/C17): the CA bundle (etc/certs/root-ca.pem) as a value -- its
# certificates, its publication block, its content hash and the guards that decide whether it may
# be vouched for. Pure OpenSSL, no file reads and no logging, so remoted (which links it inside
# libremoted_module.so) and wazuh-manager-certs answer the same questions with the same code.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Linked into remoted_module, a SHARED library: its objects have to be position independent.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

add_library(ca_bundle STATIC src/ca_bundle.cpp)

target_include_directories(ca_bundle PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# `crypto` is the GLOBAL alias src/external/CMakeLists.txt gives the VENDORED static libcrypto.a
# (src/external/openssl), never the system one -- the same name ext_restinio links, which is where
# remoted_module gets OpenSSL from today. PUBLIC, not PRIVATE: the public header names X509 (via
# <openssl/types.h>), so every consumer needs those include directories, and a static archive
# leaves its symbols for the final link either way.
target_link_libraries(ca_bundle PUBLIC crypto)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(ca_bundle)
  add_subdirectory(test)
endif()

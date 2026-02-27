# Copyright (C) 2015, Wazuh Inc. External dependencies build orchestrator

include(ExternalProject)

# ==============================================================================
# Common settings
# ==============================================================================

set(EXTERNAL_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Detect platform
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(IS_LINUX TRUE)
  set(IS_DARWIN FALSE)
  set(IS_WINDOWS FALSE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(IS_LINUX FALSE)
  set(IS_DARWIN TRUE)
  set(IS_WINDOWS FALSE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(IS_LINUX FALSE)
  set(IS_DARWIN FALSE)
  set(IS_WINDOWS TRUE)
endif()

# Detect architecture
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
  set(IS_AARCH64 TRUE)
else()
  set(IS_AARCH64 FALSE)
endif()

# MinGW cross-compilation prefix
if(IS_WINDOWS)
  set(MINGW_PREFIX "i686-w64-mingw32-")
  set(MINGW_HOST "i686-w64-mingw32")
  set(MINGW_CC "${MINGW_PREFIX}gcc")
else()
  set(MINGW_PREFIX "")
  set(MINGW_HOST "")
  set(MINGW_CC "${CMAKE_C_COMPILER}")
endif()

# ==============================================================================
# Section 1: Autotools-based dependencies (ExternalProject_Add)
# ==============================================================================

# ------------------------------------------------------------------------------
# OpenSSL
# ------------------------------------------------------------------------------

set(OPENSSL_FLAGS "enable-weak-ssl-ciphers;no-shared")

if(IS_WINDOWS)
  set(OPENSSL_CONFIGURE_CMD ${EXTERNAL_DIR}/openssl/Configure ${OPENSSL_FLAGS}
                            mingw)
  set(OPENSSL_ENV CC=${MINGW_CC} RC=${MINGW_PREFIX}windres)
elseif(IS_DARWIN)
  if(IS_AARCH64)
    set(OPENSSL_CONFIGURE_CMD ${EXTERNAL_DIR}/openssl/Configure
                              ${OPENSSL_FLAGS} darwin64-arm64-cc)
  else()
    set(OPENSSL_CONFIGURE_CMD ${EXTERNAL_DIR}/openssl/Configure
                              ${OPENSSL_FLAGS} darwin64-x86_64-cc)
  endif()
  set(OPENSSL_ENV "")
else()
  set(OPENSSL_CONFIGURE_CMD ${EXTERNAL_DIR}/openssl/config ${OPENSSL_FLAGS})
  set(OPENSSL_ENV "")
endif()

# Check if precompiled libraries exist
if(EXISTS ${EXTERNAL_DIR}/openssl/libssl.a
   AND EXISTS ${EXTERNAL_DIR}/openssl/libcrypto.a)
  message(STATUS "Using precompiled OpenSSL libraries")
  add_custom_target(openssl_external)
else()
  ExternalProject_Add(
    openssl_external
    SOURCE_DIR ${EXTERNAL_DIR}/openssl
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env ${OPENSSL_ENV}
                      ${OPENSSL_CONFIGURE_CMD}
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} build_libs
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${EXTERNAL_DIR}/openssl/libssl.a
                     ${EXTERNAL_DIR}/openssl/libcrypto.a)

  if(IS_WINDOWS)
    find_program(MINGW_RANLIB i686-w64-mingw32-ranlib REQUIRED)
    ExternalProject_Add_Step(
      openssl_external ranlib_libs
      COMMAND ${MINGW_RANLIB} ${EXTERNAL_DIR}/openssl/libssl.a
              ${EXTERNAL_DIR}/openssl/libcrypto.a
      DEPENDEES build
      COMMENT "Running ranlib on OpenSSL libraries")
  endif()
endif()

add_library(openssl_ssl STATIC IMPORTED GLOBAL)
set_target_properties(openssl_ssl PROPERTIES IMPORTED_LOCATION
                                             ${EXTERNAL_DIR}/openssl/libssl.a)
target_include_directories(openssl_ssl
                           INTERFACE ${EXTERNAL_DIR}/openssl/include)
add_dependencies(openssl_ssl openssl_external)
add_library(ssl ALIAS openssl_ssl)

add_library(openssl_crypto STATIC IMPORTED GLOBAL)
set_target_properties(
  openssl_crypto PROPERTIES IMPORTED_LOCATION
                            ${EXTERNAL_DIR}/openssl/libcrypto.a)
target_include_directories(openssl_crypto
                           INTERFACE ${EXTERNAL_DIR}/openssl/include)
add_dependencies(openssl_crypto openssl_external)
add_library(crypto ALIAS openssl_crypto)

# Set variables for modules that use find_library()
set(OPENSSL_LIB
    ${EXTERNAL_DIR}/openssl/libssl.a
    CACHE FILEPATH "OpenSSL SSL library" FORCE)
set(OPENSSL_CRYPTO_LIB
    ${EXTERNAL_DIR}/openssl/libcrypto.a
    CACHE FILEPATH "OpenSSL Crypto library" FORCE)

# ------------------------------------------------------------------------------
# zlib
# ------------------------------------------------------------------------------

if(EXISTS ${EXTERNAL_DIR}/zlib/libz.a)
  message(STATUS "Using precompiled zlib library")
  add_custom_target(zlib_external)
else()
  if(IS_WINDOWS)
    ExternalProject_Add(
      zlib_external
      SOURCE_DIR ${EXTERNAL_DIR}/zlib
      CONFIGURE_COMMAND ${CMAKE_COMMAND} -E copy ${EXTERNAL_DIR}/zlib/zconf.h.in
                        ${EXTERNAL_DIR}/zlib/zconf.h
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -f win32/Makefile.gcc
                    PREFIX=${MINGW_PREFIX} libz.a
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/zlib/libz.a)
  else()
    ExternalProject_Add(
      zlib_external
      SOURCE_DIR ${EXTERNAL_DIR}/zlib
      CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env CFLAGS=-fPIC
                        ${EXTERNAL_DIR}/zlib/configure
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} libz.a
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/zlib/libz.a)
  endif()
endif()

add_library(ext_zlib STATIC IMPORTED GLOBAL)
set_target_properties(ext_zlib PROPERTIES IMPORTED_LOCATION
                                          ${EXTERNAL_DIR}/zlib/libz.a)
add_dependencies(ext_zlib zlib_external)
target_include_directories(ext_zlib INTERFACE ${EXTERNAL_DIR}/zlib)

# ------------------------------------------------------------------------------
# minizip (depends on zlib, server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/zlib/contrib/minizip/libminizip.a)
    message(STATUS "Using precompiled minizip library")
    add_custom_target(minizip_external)
  else()
    ExternalProject_Add(
      minizip_external
      SOURCE_DIR ${EXTERNAL_DIR}/zlib/contrib/minizip
      CONFIGURE_COMMAND ""
      BUILD_COMMAND
        ${CMAKE_C_COMPILER} -fPIC -c
        ${EXTERNAL_DIR}/zlib/contrib/minizip/unzip.c
        ${EXTERNAL_DIR}/zlib/contrib/minizip/ioapi.c -I${EXTERNAL_DIR}/zlib
      COMMAND ar rcs ${EXTERNAL_DIR}/zlib/contrib/minizip/libminizip.a unzip.o
              ioapi.o
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      DEPENDS zlib_external
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/zlib/contrib/minizip/libminizip.a)
  endif()

  add_library(ext_minizip STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_minizip PROPERTIES IMPORTED_LOCATION
                           ${EXTERNAL_DIR}/zlib/contrib/minizip/libminizip.a)
  add_dependencies(ext_minizip minizip_external)
  target_include_directories(ext_minizip INTERFACE ${EXTERNAL_DIR}/zlib/contrib)
  add_library(minizip ALIAS ext_minizip)
endif()

# ------------------------------------------------------------------------------
# libyaml
# ------------------------------------------------------------------------------

if(IS_WINDOWS)
  set(LIBYAML_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      CC=${MINGW_CC}
      CFLAGS=-fPIC
      ${EXTERNAL_DIR}/libyaml/configure
      --host=${MINGW_HOST}
      --enable-static=yes)
else()
  set(LIBYAML_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      CFLAGS=-fPIC
      ${EXTERNAL_DIR}/libyaml/configure
      --enable-static=yes
      --enable-shared=no)
endif()

if(EXISTS ${EXTERNAL_DIR}/libyaml/src/.libs/libyaml.a)
  message(STATUS "Using precompiled libyaml library")
  add_custom_target(libyaml_external)
else()
  ExternalProject_Add(
    libyaml_external
    SOURCE_DIR ${EXTERNAL_DIR}/libyaml
    CONFIGURE_COMMAND ${LIBYAML_CONFIGURE_CMD}
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libyaml/src/.libs/libyaml.a)
endif()

add_library(ext_libyaml STATIC IMPORTED GLOBAL)
set_target_properties(
  ext_libyaml PROPERTIES IMPORTED_LOCATION
                         ${EXTERNAL_DIR}/libyaml/src/.libs/libyaml.a)
add_dependencies(ext_libyaml libyaml_external)

# ------------------------------------------------------------------------------
# curl (depends on OpenSSL)
# ------------------------------------------------------------------------------

if(IS_WINDOWS)
  set(CURL_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      CFLAGS=-fPIC
      CC=${MINGW_CC}
      ${EXTERNAL_DIR}/curl/configure
      --host=${MINGW_HOST}
      PREFIX=${MINGW_PREFIX}
      --enable-static=yes
      --disable-shared
      --with-schannel
      --disable-ldap
      --without-libidn2
      --without-libpsl
      --without-zstd)
elseif(IS_LINUX)
  if(IS_AARCH64)
    set(CURL_BUILD_FLAG "--build=${CMAKE_SYSTEM_PROCESSOR}-unknown-linux-gnu")
  else()
    set(CURL_BUILD_FLAG "")
  endif()
  set(CURL_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      "CPPFLAGS=-fPIC -I${EXTERNAL_DIR}/openssl/include"
      "LDFLAGS=-L${EXTERNAL_DIR}/openssl"
      "LIBS=-ldl -lpthread"
      ${EXTERNAL_DIR}/curl/configure
      --with-openssl=${EXTERNAL_DIR}/openssl
      --disable-ldap
      --without-libidn2
      --without-libpsl
      --without-brotli
      --without-nghttp2
      --without-zstd
      ${CURL_BUILD_FLAG})
else() # Darwin
  set(CURL_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      "CPPFLAGS=-fPIC -I${EXTERNAL_DIR}/openssl/include"
      "LDFLAGS=-L${EXTERNAL_DIR}/openssl"
      "LIBS=-lpthread"
      ${EXTERNAL_DIR}/curl/configure
      --with-openssl=${EXTERNAL_DIR}/openssl
      --disable-ldap
      --without-libidn2
      --without-brotli
      --without-nghttp2
      --without-librtmp
      --without-zstd
      --without-libpsl)
endif()

if(EXISTS ${EXTERNAL_DIR}/curl/lib/.libs/libcurl.a)
  message(STATUS "Using precompiled curl library")
  add_custom_target(curl_external)
else()
  ExternalProject_Add(
    curl_external
    SOURCE_DIR ${EXTERNAL_DIR}/curl
    CONFIGURE_COMMAND ${CURL_CONFIGURE_CMD}
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -C lib
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    DEPENDS openssl_external
    BUILD_BYPRODUCTS ${EXTERNAL_DIR}/curl/lib/.libs/libcurl.a)
endif()

add_library(ext_curl STATIC IMPORTED GLOBAL)
set_target_properties(
  ext_curl PROPERTIES IMPORTED_LOCATION
                      ${EXTERNAL_DIR}/curl/lib/.libs/libcurl.a)
add_dependencies(ext_curl curl_external)

# ------------------------------------------------------------------------------
# PCRE2
# ------------------------------------------------------------------------------

if(IS_WINDOWS)
  set(PCRE2_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      CFLAGS=-fPIC
      CC=${MINGW_CC}
      ${EXTERNAL_DIR}/libpcre2/configure
      --enable-jit=no
      --host=${MINGW_HOST}
      --disable-shared)
else()
  set(PCRE2_CONFIGURE_CMD
      ${CMAKE_COMMAND}
      -E
      env
      CFLAGS=-fPIC
      ${EXTERNAL_DIR}/libpcre2/configure
      --enable-jit=auto
      --disable-shared)
endif()

if(EXISTS ${EXTERNAL_DIR}/libpcre2/.libs/libpcre2-8.a)
  message(STATUS "Using precompiled PCRE2 library")
  add_custom_target(pcre2_external)
else()
  ExternalProject_Add(
    pcre2_external
    SOURCE_DIR ${EXTERNAL_DIR}/libpcre2
    CONFIGURE_COMMAND ${PCRE2_CONFIGURE_CMD}
    BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${EXTERNAL_DIR}/libpcre2/include
    COMMAND ${CMAKE_COMMAND} -E copy ${EXTERNAL_DIR}/libpcre2/src/pcre2.h
            ${EXTERNAL_DIR}/libpcre2/include/pcre2.h
    BUILD_IN_SOURCE TRUE
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libpcre2/.libs/libpcre2-8.a)
endif()

add_library(ext_pcre2 STATIC IMPORTED GLOBAL)
set_target_properties(
  ext_pcre2 PROPERTIES IMPORTED_LOCATION
                       ${EXTERNAL_DIR}/libpcre2/.libs/libpcre2-8.a)
add_dependencies(ext_pcre2 pcre2_external)
add_library(pcre2-8 ALIAS ext_pcre2)

# ------------------------------------------------------------------------------
# audit-userspace (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  if(EXISTS ${EXTERNAL_DIR}/audit-userspace/lib/.libs/libaudit.a)
    message(STATUS "Using precompiled audit library")
    add_custom_target(audit_external)
  else()
    ExternalProject_Add(
      audit_external
      SOURCE_DIR ${EXTERNAL_DIR}/audit-userspace
      CONFIGURE_COMMAND ${EXTERNAL_DIR}/audit-userspace/autogen.sh
      COMMAND ${CMAKE_COMMAND} -E env CFLAGS=-fPIC
              ${EXTERNAL_DIR}/audit-userspace/configure --with-libcap-ng=no
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} -C lib
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/audit-userspace/lib/.libs/libaudit.a)
  endif()

  add_library(ext_audit STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_audit PROPERTIES IMPORTED_LOCATION
                         ${EXTERNAL_DIR}/audit-userspace/lib/.libs/libaudit.a)
  add_dependencies(ext_audit audit_external)
endif()

# ------------------------------------------------------------------------------
# libffi (not for agent target)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT)
  # libffi builds in architecture-specific subdirectory (e.g.,
  # x86_64-pc-linux-gnu) Find precompiled library in any architecture
  # subdirectory
  file(GLOB LIBFFI_PRECOMPILED "${EXTERNAL_DIR}/libffi/*/.libs/libffi.a")
  if(LIBFFI_PRECOMPILED)
    list(GET LIBFFI_PRECOMPILED 0 LIBFFI_LIBRARY)
    message(STATUS "Using precompiled libffi library: ${LIBFFI_LIBRARY}")
    add_custom_target(libffi_external)
  else()
    # Detect host architecture triplet for BUILD_BYPRODUCTS
    execute_process(
      COMMAND ${EXTERNAL_DIR}/libffi/config.guess
      OUTPUT_VARIABLE LIBFFI_HOST
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    ExternalProject_Add(
      libffi_external
      SOURCE_DIR ${EXTERNAL_DIR}/libffi
      CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env CFLAGS=-fPIC
                        ${EXTERNAL_DIR}/libffi/configure
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libffi/${LIBFFI_HOST}/.libs/libffi.a)

    set(LIBFFI_LIBRARY ${EXTERNAL_DIR}/libffi/${LIBFFI_HOST}/.libs/libffi.a)
  endif()

  add_library(ext_libffi STATIC IMPORTED GLOBAL)
  set_target_properties(ext_libffi PROPERTIES IMPORTED_LOCATION
                                              ${LIBFFI_LIBRARY})
  add_dependencies(ext_libffi libffi_external)
endif()

# ------------------------------------------------------------------------------
# libplist (macOS only)
# ------------------------------------------------------------------------------

if(IS_DARWIN)
  if(EXISTS ${EXTERNAL_DIR}/libplist/bin/lib/libplist-2.0.a)
    message(STATUS "Using precompiled libplist library")
    add_custom_target(libplist_external)
  else()
    ExternalProject_Add(
      libplist_external
      SOURCE_DIR ${EXTERNAL_DIR}/libplist
      CONFIGURE_COMMAND ${EXTERNAL_DIR}/libplist/autogen.sh
                        --prefix=${EXTERNAL_DIR}/libplist/bin
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
      INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
      BUILD_IN_SOURCE TRUE
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libplist/bin/lib/libplist-2.0.a)
  endif()

  add_library(ext_libplist STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_libplist PROPERTIES IMPORTED_LOCATION
                            ${EXTERNAL_DIR}/libplist/bin/lib/libplist-2.0.a)
  add_dependencies(ext_libplist libplist_external)
  add_library(plist ALIAS ext_libplist)
endif()

# ------------------------------------------------------------------------------
# bzip2 (not winagent)
# ------------------------------------------------------------------------------

if(NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/bzip2/libbz2.a)
    message(STATUS "Using precompiled bzip2 library")
    add_custom_target(bzip2_external)
  else()
    ExternalProject_Add(
      bzip2_external
      SOURCE_DIR ${EXTERNAL_DIR}/bzip2
      CONFIGURE_COMMAND ""
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
                    "CFLAGS=-fpic -Wall -O2 -D_FILE_OFFSET_BITS=64" libbz2.a
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/bzip2/libbz2.a)
  endif()

  add_library(ext_bzip2 STATIC IMPORTED GLOBAL)
  set_target_properties(ext_bzip2 PROPERTIES IMPORTED_LOCATION
                                             ${EXTERNAL_DIR}/bzip2/libbz2.a)
  add_dependencies(ext_bzip2 bzip2_external)
endif()

# ------------------------------------------------------------------------------
# libarchive (Linux only, not winagent)
# ------------------------------------------------------------------------------

if(IS_LINUX AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/libarchive/.libs/libarchive.a)
    message(STATUS "Using precompiled libarchive library")
    add_custom_target(libarchive_external)
  else()
    ExternalProject_Add(
      libarchive_external
      SOURCE_DIR ${EXTERNAL_DIR}/libarchive
      CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env CPPFLAGS=-fPIC
        ${EXTERNAL_DIR}/libarchive/configure --disable-acl --without-expat
        --without-iconv --without-xml2 --without-lz4 --without-lzma
        --without-zstd --without-bz2lib --without-openssl --without-libb2
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} libarchive.la
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libarchive/.libs/libarchive.a)
  endif()

  add_library(ext_libarchive STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_libarchive PROPERTIES IMPORTED_LOCATION
                              ${EXTERNAL_DIR}/libarchive/.libs/libarchive.a)
  add_dependencies(ext_libarchive libarchive_external)
  target_include_directories(ext_libarchive
                             INTERFACE ${EXTERNAL_DIR}/libarchive/libarchive)
endif()

# ------------------------------------------------------------------------------
# Berkeley DB (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  if(EXISTS ${EXTERNAL_DIR}/libdb/build_unix/.libs/libdb-18.1.a)
    message(STATUS "Using precompiled Berkeley DB library")
    add_custom_target(libdb_external)
  else()
    ExternalProject_Add(
      libdb_external
      SOURCE_DIR ${EXTERNAL_DIR}/libdb/build_unix
      CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env CPPFLAGS=-fPIC
        ${EXTERNAL_DIR}/libdb/dist/configure --with-cryptography=no
        --disable-queue --disable-heap --disable-partition
        --disable-mutexsupport --disable-replication --disable-verify
        --disable-statistics ac_cv_func_pthread_yield=no
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} libdb.a
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libdb/build_unix/.libs/libdb-18.1.a)
  endif()

  add_library(ext_libdb STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_libdb PROPERTIES IMPORTED_LOCATION
                         ${EXTERNAL_DIR}/libdb/build_unix/.libs/libdb-18.1.a)
  add_dependencies(ext_libdb libdb_external)
endif()

# ------------------------------------------------------------------------------
# Lua (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  if(EXISTS ${EXTERNAL_DIR}/lua/liblua.a)
    message(STATUS "Using precompiled Lua library")
    add_custom_target(lua_external)
  else()
    ExternalProject_Add(
      lua_external
      SOURCE_DIR ${EXTERNAL_DIR}/lua
      CONFIGURE_COMMAND ""
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM} all "MYCFLAGS=-fPIC -DLUA_USE_LINUX"
                    "MYLIBS=-lm -ldl"
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/lua/liblua.a)
  endif()

  add_library(ext_lua STATIC IMPORTED GLOBAL)
  set_target_properties(ext_lua PROPERTIES IMPORTED_LOCATION
                                           ${EXTERNAL_DIR}/lua/liblua.a)
  add_dependencies(ext_lua lua_external)
endif()

# ------------------------------------------------------------------------------
# dbus (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  set(DBUS_CONFIG_OPTS
      --enable-static
      --disable-shared
      --disable-doxygen-docs
      --disable-xml-docs
      --disable-dependency-tracking
      --disable-systemd
      --prefix=${EXTERNAL_DIR}/dbus
      --includedir=${EXTERNAL_DIR}/dbus/include
      --libdir=${EXTERNAL_DIR}/dbus/lib
      --with-system-socket=/run/dbus/system_bus_socket)

  if(EXISTS ${EXTERNAL_DIR}/dbus/lib/libdbus-1.a)
    message(STATUS "Using precompiled D-Bus library")
    add_custom_target(dbus_external)
  else()
    ExternalProject_Add(
      dbus_external
      SOURCE_DIR ${EXTERNAL_DIR}/dbus
      CONFIGURE_COMMAND
        ${CMAKE_COMMAND} -E env CFLAGS=-fPIC CXXFLAGS=-fPIC LDFLAGS=-fPIC
        ${EXTERNAL_DIR}/dbus/configure ${DBUS_CONFIG_OPTS}
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
      INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
      BUILD_IN_SOURCE TRUE
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/dbus/lib/libdbus-1.a)
  endif()

  add_library(ext_dbus STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_dbus PROPERTIES IMPORTED_LOCATION ${EXTERNAL_DIR}/dbus/lib/libdbus-1.a)
  add_dependencies(ext_dbus dbus_external)
endif()

# ------------------------------------------------------------------------------
# jemalloc (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/jemalloc/lib/libjemalloc.so.2)
    message(STATUS "Using precompiled jemalloc library")
    add_custom_target(jemalloc_external)
  else()
    if(EXISTS ${EXTERNAL_DIR}/jemalloc/configure)
      set(JEMALLOC_CONFIGURE_CMD ${EXTERNAL_DIR}/jemalloc/configure)
    else()
      set(JEMALLOC_CONFIGURE_CMD ${EXTERNAL_DIR}/jemalloc/autogen.sh)
    endif()

    ExternalProject_Add(
      jemalloc_external
      SOURCE_DIR ${EXTERNAL_DIR}/jemalloc
      CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env LDFLAGS=-s
                        ${JEMALLOC_CONFIGURE_CMD} --disable-static --disable-cxx
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
      BUILD_IN_SOURCE TRUE
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/jemalloc/lib/libjemalloc.so.2)
  endif()

  add_library(ext_jemalloc SHARED IMPORTED GLOBAL)
  set_target_properties(
    ext_jemalloc PROPERTIES IMPORTED_LOCATION
                            ${EXTERNAL_DIR}/jemalloc/lib/libjemalloc.so.2)
  add_dependencies(ext_jemalloc jemalloc_external)
endif()

# ==============================================================================
# Section 2: CMake-based dependencies (ExternalProject_Add)
# ==============================================================================

# ------------------------------------------------------------------------------
# RocksDB (server only, shared lib)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/rocksdb/build/librocksdb.so)
    message(STATUS "Using precompiled RocksDB library")
    add_custom_target(rocksdb_external)
  else()
    ExternalProject_Add(
      rocksdb_external
      SOURCE_DIR ${EXTERNAL_DIR}/rocksdb
      BINARY_DIR ${EXTERNAL_DIR}/rocksdb/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
                 -DWITH_GFLAGS=0
                 -DWITH_TESTS=0
                 -DWITH_BENCHMARK_TOOLS=0
                 -DWITH_TOOLS=0
                 -DUSE_RTTI=1
                 -DROCKSDB_BUILD_SHARED=1
                 -DWITH_BZ2=1
                 -DBZIP2_INCLUDE_DIR=${EXTERNAL_DIR}/bzip2
                 -DBZIP2_LIBRARIES=${EXTERNAL_DIR}/bzip2/libbz2.a
                 -DCMAKE_POSITION_INDEPENDENT_CODE=1
                 -DWITH_ALL_TESTS=0
                 -DWITH_RUNTIME_DEBUG=0
                 -DWITH_TRACE_TOOLS=0
                 -DPORTABLE=1
      INSTALL_COMMAND ""
      DEPENDS bzip2_external
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/rocksdb/build/librocksdb.so)
  endif()

  add_library(ext_rocksdb SHARED IMPORTED GLOBAL)
  set_target_properties(
    ext_rocksdb PROPERTIES IMPORTED_LOCATION
                           ${EXTERNAL_DIR}/rocksdb/build/librocksdb.so)
  add_dependencies(ext_rocksdb rocksdb_external)
  target_include_directories(ext_rocksdb
                             INTERFACE ${EXTERNAL_DIR}/rocksdb/include)
  add_library(rocksdb ALIAS ext_rocksdb)
endif()

# ------------------------------------------------------------------------------
# simdjson (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/simdjson/build/libsimdjson.a)
    message(STATUS "Using precompiled simdjson library")
    add_custom_target(simdjson_external)
  else()
    ExternalProject_Add(
      simdjson_external
      SOURCE_DIR ${EXTERNAL_DIR}/simdjson
      BINARY_DIR ${EXTERNAL_DIR}/simdjson/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DSIMDJSON_DEVELOPER_MODE=OFF
                 -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=1
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/simdjson/build/libsimdjson.a)
  endif()

  add_library(ext_simdjson STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_simdjson PROPERTIES IMPORTED_LOCATION
                            ${EXTERNAL_DIR}/simdjson/build/libsimdjson.a)
  add_dependencies(ext_simdjson simdjson_external)
  target_include_directories(ext_simdjson
                             INTERFACE ${EXTERNAL_DIR}/simdjson/include)
endif()

# ------------------------------------------------------------------------------
# abseil-cpp (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/abseil-cpp/build/build_result/lib64/libabsl_base.a
     OR EXISTS ${EXTERNAL_DIR}/abseil-cpp/build/build_result/lib/libabsl_base.a)
    message(STATUS "Using precompiled abseil-cpp libraries")
    add_custom_target(abseilcpp_external)
  else()
    ExternalProject_Add(
      abseilcpp_external
      SOURCE_DIR ${EXTERNAL_DIR}/abseil-cpp
      BINARY_DIR ${EXTERNAL_DIR}/abseil-cpp/build
      CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DABSL_BUILD_TESTING=OFF
        -DABSL_USE_GOOGLETEST_HEAD=OFF
        -DCMAKE_CXX_STANDARD=17
        -DCMAKE_POSITION_INDEPENDENT_CODE=1
        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_DIR}/abseil-cpp/build/build_result
      INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
      BUILD_BYPRODUCTS
        ${EXTERNAL_DIR}/abseil-cpp/build/build_result/lib/libabsl_base.a)
  endif()
  # Note: abseil produces many libabsl_*.a files. Consumers should link against
  # the install prefix directory.
endif()

# ------------------------------------------------------------------------------
# RE2 (server only, depends on abseil-cpp)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/re2/build/libre2.a)
    message(STATUS "Using precompiled RE2 library")
    add_custom_target(re2_external)
  else()
    ExternalProject_Add(
      re2_external
      SOURCE_DIR ${EXTERNAL_DIR}/re2
      BINARY_DIR ${EXTERNAL_DIR}/re2/build
      CMAKE_ARGS
        -DCMAKE_BUILD_TYPE=Release
        -DRE2_BUILD_TESTING=OFF
        -DCMAKE_CXX_STANDARD=17
        -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_PREFIX_PATH=${EXTERNAL_DIR}/abseil-cpp/build/build_result
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DCMAKE_INSTALL_PREFIX=${EXTERNAL_DIR}/re2/build/result
      INSTALL_COMMAND ""
      DEPENDS abseilcpp_external
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/re2/build/libre2.a)
  endif()

  add_library(ext_re2 STATIC IMPORTED GLOBAL)
  set_target_properties(ext_re2 PROPERTIES IMPORTED_LOCATION
                                           ${EXTERNAL_DIR}/re2/build/libre2.a)
  add_dependencies(ext_re2 re2_external)
endif()

# ------------------------------------------------------------------------------
# FlatBuffers (all targets need headers; server links the static lib)
# ------------------------------------------------------------------------------

if(EXISTS ${EXTERNAL_DIR}/flatbuffers/build/libflatbuffers.a
   AND EXISTS ${EXTERNAL_DIR}/flatbuffers/build/flatc)
  message(STATUS "Using precompiled FlatBuffers library")
  add_custom_target(flatbuffers_external)
else()
  ExternalProject_Add(
    flatbuffers_external
    SOURCE_DIR ${EXTERNAL_DIR}/flatbuffers
    BINARY_DIR ${EXTERNAL_DIR}/flatbuffers/build
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DFLATBUFFERS_BUILD_TESTS=0
               -DFLATBUFFERS_INSTALL=0 -DCMAKE_POSITION_INDEPENDENT_CODE=1
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${EXTERNAL_DIR}/flatbuffers/build/libflatbuffers.a
                     ${EXTERNAL_DIR}/flatbuffers/build/flatc)
endif()

add_library(ext_flatbuffers STATIC IMPORTED GLOBAL)
set_target_properties(
  ext_flatbuffers PROPERTIES IMPORTED_LOCATION
                             ${EXTERNAL_DIR}/flatbuffers/build/libflatbuffers.a)
add_dependencies(ext_flatbuffers flatbuffers_external)

# ------------------------------------------------------------------------------
# spdlog (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/spdlog/build/libspdlog.a)
    message(STATUS "Using precompiled spdlog library")
    add_custom_target(spdlog_external)
  else()
    ExternalProject_Add(
      spdlog_external
      SOURCE_DIR ${EXTERNAL_DIR}/spdlog
      BINARY_DIR ${EXTERNAL_DIR}/spdlog/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
                 -DSPDLOG_BUILD_EXAMPLE=OFF
                 -DSPDLOG_BUILD_TESTS=OFF
                 -DSPDLOG_BUILD_BENCH=OFF
                 -DSPDLOG_FMT_EXTERNAL=OFF
                 -DBUILD_SHARED_LIBS=OFF
                 -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/spdlog/build/libspdlog.a)
  endif()

  add_library(ext_spdlog STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_spdlog PROPERTIES IMPORTED_LOCATION
                          ${EXTERNAL_DIR}/spdlog/build/libspdlog.a)
  add_dependencies(ext_spdlog spdlog_external)
endif()

# ------------------------------------------------------------------------------
# yaml-cpp (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/yaml-cpp/build/libyaml-cpp.a)
    message(STATUS "Using precompiled yamlcpp library")
    add_custom_target(yamlcpp_external)
  else()
    ExternalProject_Add(
      yamlcpp_external
      SOURCE_DIR ${EXTERNAL_DIR}/yaml-cpp
      BINARY_DIR ${EXTERNAL_DIR}/yaml-cpp/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TOOLS=OFF
                 -DYAML_CPP_BUILD_TESTS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=1
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/yaml-cpp/build/libyaml-cpp.a)
  endif()

  add_library(ext_yamlcpp STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_yamlcpp PROPERTIES IMPORTED_LOCATION
                           ${EXTERNAL_DIR}/yaml-cpp/build/libyaml-cpp.a)
  add_dependencies(ext_yamlcpp yamlcpp_external)
endif()

# ------------------------------------------------------------------------------
# pugixml (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/pugixml/build/libpugixml.a)
    message(STATUS "Using precompiled pugixml library")
    add_custom_target(pugixml_external)
  else()
    ExternalProject_Add(
      pugixml_external
      SOURCE_DIR ${EXTERNAL_DIR}/pugixml
      BINARY_DIR ${EXTERNAL_DIR}/pugixml/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DPUGIXML_BUILD_TESTS=OFF
                 -DCMAKE_POSITION_INDEPENDENT_CODE=1
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/pugixml/build/libpugixml.a)
  endif()

  add_library(ext_pugixml STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_pugixml PROPERTIES IMPORTED_LOCATION
                           ${EXTERNAL_DIR}/pugixml/build/libpugixml.a)
  add_dependencies(ext_pugixml pugixml_external)
endif()

# ------------------------------------------------------------------------------
# libmaxminddb (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/libmaxminddb/build/libmaxminddb.a)
    message(STATUS "Using precompiled libmaxminddb library")
    add_custom_target(maxminddb_external)
  else()
    file(MAKE_DIRECTORY ${EXTERNAL_DIR}/libmaxminddb/build/generated)

    ExternalProject_Add(
      maxminddb_external
      SOURCE_DIR ${EXTERNAL_DIR}/libmaxminddb
      BINARY_DIR ${EXTERNAL_DIR}/libmaxminddb/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
                 -DCMAKE_POSITION_INDEPENDENT_CODE=1
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libmaxminddb/build/libmaxminddb.a)
  endif()

  add_library(ext_maxminddb STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_maxminddb PROPERTIES IMPORTED_LOCATION
                             ${EXTERNAL_DIR}/libmaxminddb/build/libmaxminddb.a)
  add_dependencies(ext_maxminddb maxminddb_external)
endif()

# ------------------------------------------------------------------------------
# protobuf (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/protobuf/build/libprotobuf.a)
    message(STATUS "Using precompiled protobuf library")
    add_custom_target(protobuf_external)
  else()
    ExternalProject_Add(
      protobuf_external
      SOURCE_DIR ${EXTERNAL_DIR}/protobuf
      BINARY_DIR ${EXTERNAL_DIR}/protobuf/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -Dprotobuf_BUILD_TESTS=OFF
                 -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/protobuf/build/libprotobuf.a)
  endif()

  add_library(ext_protobuf STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_protobuf PROPERTIES IMPORTED_LOCATION
                            ${EXTERNAL_DIR}/protobuf/build/libprotobuf.a)
  add_dependencies(ext_protobuf protobuf_external)
endif()

# ------------------------------------------------------------------------------
# date (Howard Hinnant, server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/date/build/libdate-tz.a)
    message(STATUS "Using precompiled date library")
    add_custom_target(date_external)
  else()
    ExternalProject_Add(
      date_external
      SOURCE_DIR ${EXTERNAL_DIR}/date
      BINARY_DIR ${EXTERNAL_DIR}/date/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
                 -DENABLE_DATE_TESTING=OFF
                 -DUSE_SYSTEM_TZ_DB=OFF
                 -DBUILD_TZ_LIB=ON
                 -DBUILD_SHARED_LIBS=OFF
                 -DCMAKE_POSITION_INDEPENDENT_CODE=ON
                 -DCURL_INCLUDE_DIR=${EXTERNAL_DIR}/curl/include
                 -DCURL_LIBRARY=${EXTERNAL_DIR}/curl/lib/.libs/libcurl.a
      INSTALL_COMMAND ""
      DEPENDS curl_external
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/date/build/libdate-tz.a)
  endif()

  add_library(ext_date STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_date PROPERTIES IMPORTED_LOCATION
                        ${EXTERNAL_DIR}/date/build/libdate-tz.a)
  add_dependencies(ext_date date_external)
endif()

# ------------------------------------------------------------------------------
# fmt (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/fmt/build/libfmt.a)
    message(STATUS "Using precompiled fmt library")
    add_custom_target(fmt_external)
  else()
    ExternalProject_Add(
      fmt_external
      SOURCE_DIR ${EXTERNAL_DIR}/fmt
      BINARY_DIR ${EXTERNAL_DIR}/fmt/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DFMT_TEST=OFF -DFMT_DOC=OFF
                 -DBUILD_SHARED_LIBS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/fmt/build/libfmt.a)
  endif()

  add_library(ext_fmt STATIC IMPORTED GLOBAL)
  set_target_properties(ext_fmt PROPERTIES IMPORTED_LOCATION
                                           ${EXTERNAL_DIR}/fmt/build/libfmt.a)
  add_dependencies(ext_fmt fmt_external)
endif()

# ------------------------------------------------------------------------------
# lzma (server only)
# ------------------------------------------------------------------------------

if(NOT IS_AGENT AND NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/lzma/build/liblzma.a)
    message(STATUS "Using precompiled lzma library")
    add_custom_target(lzma_external)
  else()
    ExternalProject_Add(
      lzma_external
      SOURCE_DIR ${EXTERNAL_DIR}/lzma
      BINARY_DIR ${EXTERNAL_DIR}/lzma/build
      CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=0
                 -DCMAKE_POSITION_INDEPENDENT_CODE=1
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/lzma/build/liblzma.a)
  endif()

  add_library(ext_lzma STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_lzma PROPERTIES IMPORTED_LOCATION ${EXTERNAL_DIR}/lzma/build/liblzma.a)
  add_dependencies(ext_lzma lzma_external)
  target_include_directories(ext_lzma
                             INTERFACE ${EXTERNAL_DIR}/lzma/src/liblzma/api)
  add_library(lzma ALIAS ext_lzma)
endif()

# ------------------------------------------------------------------------------
# popt (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  if(EXISTS ${EXTERNAL_DIR}/popt/build/output/src/.libs/libpopt.a)
    message(STATUS "Using precompiled popt library")
    add_custom_target(popt_external)
  else()
    ExternalProject_Add(
      popt_external
      SOURCE_DIR ${EXTERNAL_DIR}/popt
      BINARY_DIR ${EXTERNAL_DIR}/popt/build
      CMAKE_ARGS ""
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/popt/build/output/src/.libs/libpopt.a)
  endif()

  add_library(ext_popt STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_popt PROPERTIES IMPORTED_LOCATION
                        ${EXTERNAL_DIR}/popt/build/output/src/.libs/libpopt.a)
  add_dependencies(ext_popt popt_external)
endif()

# ------------------------------------------------------------------------------
# libbpf-bootstrap (Linux only, not server, not winagent)
# ------------------------------------------------------------------------------

if(IS_LINUX AND IS_AGENT)
  if(EXISTS ${EXTERNAL_DIR}/libbpf-bootstrap/build/modern.bpf.o)
    message(STATUS "Using precompiled libbpf-bootstrap")
    add_custom_target(libbpf_external)
  else()
    ExternalProject_Add(
      libbpf_external
      SOURCE_DIR ${EXTERNAL_DIR}/libbpf-bootstrap
      BINARY_DIR ${EXTERNAL_DIR}/libbpf-bootstrap/build
      CMAKE_ARGS ""
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/libbpf-bootstrap/build/modern.bpf.o)
  endif()
endif()

# ------------------------------------------------------------------------------
# GoogleTest (test builds only)
# ------------------------------------------------------------------------------

if(UNIT_TEST OR WAZUH_ENGINE_TEST)
  if(IS_WINDOWS)
    find_program(FULL_RANLIB ${CMAKE_RANLIB} REQUIRED)
    set(GTEST_CMAKE_ARGS
        -DCMAKE_SYSTEM_NAME=Windows
        -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
        -DCMAKE_RC_COMPILER=${CMAKE_RC_COMPILER}
        -DCMAKE_AR=${CMAKE_AR}
        -DCMAKE_RANLIB=${FULL_RANLIB}
        -DCMAKE_SHARED_LIBRARY_LINK_C_FLAGS=
        -DCMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS=)
  else()
    set(GTEST_CMAKE_ARGS "")
  endif()

  if(EXISTS ${EXTERNAL_DIR}/googletest/lib/libgtest.a
     AND EXISTS ${EXTERNAL_DIR}/googletest/lib/libgmock.a)
    message(STATUS "Using precompiled GoogleTest libraries")
    add_custom_target(googletest_external)
  else()
    ExternalProject_Add(
      googletest_external
      SOURCE_DIR ${EXTERNAL_DIR}/googletest
      BINARY_DIR ${EXTERNAL_DIR}/googletest/build
      CMAKE_ARGS -DBUILD_GMOCK=ON -DBUILD_SHARED_LIBS=0 ${GTEST_CMAKE_ARGS}
      INSTALL_COMMAND
        ${CMAKE_COMMAND} -E copy_directory ${EXTERNAL_DIR}/googletest/build/lib
        ${EXTERNAL_DIR}/googletest/lib
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/googletest/build/lib/libgtest.a
                       ${EXTERNAL_DIR}/googletest/build/lib/libgmock.a)

    if(IS_WINDOWS)
      ExternalProject_Add_Step(
        googletest_external ranlib_libs
        COMMAND ${FULL_RANLIB} ${EXTERNAL_DIR}/googletest/lib/libgtest.a
        COMMAND ${FULL_RANLIB} ${EXTERNAL_DIR}/googletest/lib/libgtest_main.a
        COMMAND ${FULL_RANLIB} ${EXTERNAL_DIR}/googletest/lib/libgmock.a
        COMMAND ${FULL_RANLIB} ${EXTERNAL_DIR}/googletest/lib/libgmock_main.a
        DEPENDEES install
        COMMENT "Running ranlib on GoogleTest libraries")
    endif()
  endif()

  add_library(gtest STATIC IMPORTED GLOBAL)
  set_target_properties(
    gtest PROPERTIES IMPORTED_LOCATION
                     ${EXTERNAL_DIR}/googletest/lib/libgtest.a)
  add_dependencies(gtest googletest_external)
  add_library(gtestd ALIAS gtest)

  add_library(gtest_main STATIC IMPORTED GLOBAL)
  set_target_properties(
    gtest_main PROPERTIES IMPORTED_LOCATION
                          ${EXTERNAL_DIR}/googletest/lib/libgtest_main.a)
  add_dependencies(gtest_main googletest_external)
  add_library(gtest_maind ALIAS gtest_main)

  add_library(gmock STATIC IMPORTED GLOBAL)
  set_target_properties(
    gmock PROPERTIES IMPORTED_LOCATION
                     ${EXTERNAL_DIR}/googletest/lib/libgmock.a)
  add_dependencies(gmock googletest_external)
  add_library(gmockd ALIAS gmock)

  add_library(gmock_main STATIC IMPORTED GLOBAL)
  set_target_properties(
    gmock_main PROPERTIES IMPORTED_LOCATION
                          ${EXTERNAL_DIR}/googletest/lib/libgmock_main.a)
  add_dependencies(gmock_main googletest_external)
  add_library(gmock_maind ALIAS gmock_main)
endif()

# ------------------------------------------------------------------------------
# Google Benchmark (test builds only)
# ------------------------------------------------------------------------------

if(UNIT_TEST OR WAZUH_ENGINE_TEST)
  if(EXISTS ${EXTERNAL_DIR}/benchmark/build/src/libbenchmark.a)
    message(STATUS "Using precompiled benchmark library")
    add_custom_target(benchmark_external)
  else()
    ExternalProject_Add(
      benchmark_external
      SOURCE_DIR ${EXTERNAL_DIR}/benchmark
      BINARY_DIR ${EXTERNAL_DIR}/benchmark/build
      CMAKE_ARGS -DBENCHMARK_ENABLE_TESTING=0 ${CMAKE_OPTS}
      INSTALL_COMMAND ""
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/benchmark/build/src/libbenchmark.a)
  endif()
endif()

# ==============================================================================
# Section 3: Manually compiled dependencies (add_library STATIC)
# ==============================================================================

# ------------------------------------------------------------------------------
# cJSON
# ------------------------------------------------------------------------------

if(EXISTS ${EXTERNAL_DIR}/cJSON/libcjson.a)
  message(STATUS "Using precompiled cJSON library")
  add_library(ext_cjson STATIC IMPORTED GLOBAL)
  set_target_properties(ext_cjson PROPERTIES IMPORTED_LOCATION
                                             ${EXTERNAL_DIR}/cJSON/libcjson.a)
  target_include_directories(ext_cjson INTERFACE ${EXTERNAL_DIR}/cJSON)
else()
  add_library(ext_cjson STATIC ${EXTERNAL_DIR}/cJSON/cJSON.c)
  target_include_directories(ext_cjson PUBLIC ${EXTERNAL_DIR}/cJSON)
  set_target_properties(ext_cjson PROPERTIES POSITION_INDEPENDENT_CODE ON
                                             C_STANDARD 99)
endif()
add_library(cjson ALIAS ext_cjson)

# ------------------------------------------------------------------------------
# SQLite
# ------------------------------------------------------------------------------

if(EXISTS ${EXTERNAL_DIR}/sqlite/libsqlite3.a)
  message(STATUS "Using precompiled SQLite library")
  add_library(ext_sqlite STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_sqlite PROPERTIES IMPORTED_LOCATION ${EXTERNAL_DIR}/sqlite/libsqlite3.a)
  target_include_directories(ext_sqlite INTERFACE ${EXTERNAL_DIR}/sqlite)
else()
  add_library(ext_sqlite STATIC ${EXTERNAL_DIR}/sqlite/sqlite3.c)
  target_include_directories(ext_sqlite PUBLIC ${EXTERNAL_DIR}/sqlite)
  target_compile_definitions(ext_sqlite PRIVATE SQLITE_ENABLE_DBSTAT_VTAB=1)
  target_compile_options(ext_sqlite PRIVATE -w)
  set_target_properties(ext_sqlite PROPERTIES POSITION_INDEPENDENT_CODE ON
                                              C_STANDARD 99)
endif()
add_library(sqlite3 ALIAS ext_sqlite)
add_library(sqlite ALIAS ext_sqlite)

# ------------------------------------------------------------------------------
# msgpack (not winagent)
# ------------------------------------------------------------------------------

if(NOT IS_WINDOWS)
  if(EXISTS ${EXTERNAL_DIR}/msgpack/libmsgpack.a)
    message(STATUS "Using precompiled msgpack library")
    add_library(ext_msgpack STATIC IMPORTED GLOBAL)
    set_target_properties(
      ext_msgpack PROPERTIES IMPORTED_LOCATION
                             ${EXTERNAL_DIR}/msgpack/libmsgpack.a)
    target_include_directories(ext_msgpack
                               INTERFACE ${EXTERNAL_DIR}/msgpack/include)
  else()
    file(GLOB MSGPACK_SOURCES ${EXTERNAL_DIR}/msgpack/src/*.c)
    add_library(ext_msgpack STATIC ${MSGPACK_SOURCES})
    target_include_directories(ext_msgpack
                               PUBLIC ${EXTERNAL_DIR}/msgpack/include)
    set_target_properties(ext_msgpack PROPERTIES POSITION_INDEPENDENT_CODE ON
                                                 C_STANDARD 99)
  endif()
endif()

# ------------------------------------------------------------------------------
# procps (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  if(EXISTS ${EXTERNAL_DIR}/procps/libproc.a)
    message(STATUS "Using precompiled procps library")
    add_library(ext_procps STATIC IMPORTED GLOBAL)
    set_target_properties(
      ext_procps PROPERTIES IMPORTED_LOCATION ${EXTERNAL_DIR}/procps/libproc.a)
    target_include_directories(ext_procps INTERFACE ${EXTERNAL_DIR}/procps)
  else()
    file(GLOB PROCPS_SOURCES ${EXTERNAL_DIR}/procps/*.c)
    add_library(ext_procps STATIC ${PROCPS_SOURCES})
    target_include_directories(ext_procps PUBLIC ${EXTERNAL_DIR}/procps)
    set_target_properties(ext_procps PROPERTIES POSITION_INDEPENDENT_CODE ON
                                                C_STANDARD 99)
  endif()
  add_library(proc ALIAS ext_procps)
endif()

# ------------------------------------------------------------------------------
# libalpm/pacman (Linux only)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  if(EXISTS ${EXTERNAL_DIR}/pacman/lib/libalpm/libalpm.a)
    message(STATUS "Using precompiled libalpm library")
    add_library(ext_libalpm STATIC IMPORTED GLOBAL)
    set_target_properties(
      ext_libalpm PROPERTIES IMPORTED_LOCATION
                             ${EXTERNAL_DIR}/pacman/lib/libalpm/libalpm.a)
    target_include_directories(ext_libalpm
                               INTERFACE ${EXTERNAL_DIR}/pacman/lib/libalpm)
  else()
    file(GLOB LIBALPM_SOURCES ${EXTERNAL_DIR}/pacman/lib/libalpm/*.c)
    add_library(ext_libalpm STATIC ${LIBALPM_SOURCES})
    target_include_directories(
      ext_libalpm
      PRIVATE ${EXTERNAL_DIR}/libarchive/libarchive
              ${EXTERNAL_DIR}/openssl/include
              ${EXTERNAL_DIR}/pacman/lib/libalpm)
    target_compile_definitions(
      ext_libalpm
      PRIVATE SYSHOOKDIR="/usr/share/libalpm/hooks"
              LDCONFIG="${LDCONFIG_PATH}"
              FSSTATSTYPE=struct\ statvfs
              SCRIPTLET_SHELL="/bin/sh"
              HAVE_SYS_STATVFS_H
              LIB_VERSION=""
              PATH_MAX=4096
              HAVE_STRNLEN
              HAVE_LIBSSL)
    set_target_properties(ext_libalpm PROPERTIES POSITION_INDEPENDENT_CODE ON
                                                 C_STANDARD 99)
    add_dependencies(ext_libalpm openssl_external)
  endif()
  add_library(alpm ALIAS ext_libalpm)
endif()

# ------------------------------------------------------------------------------
# RPM (Linux only, CMake-based but with special env)
# ------------------------------------------------------------------------------

if(IS_LINUX)
  set(RPM_INC_PATHS
      "-I${EXTERNAL_DIR}/openssl/include" "-I${EXTERNAL_DIR}/zlib"
      "-I${EXTERNAL_DIR}/popt/src" "-I${EXTERNAL_DIR}/sqlite"
      "-I${EXTERNAL_DIR}/lua")
  set(RPM_LIB_PATHS
      "-L${EXTERNAL_DIR}/openssl" "-L${EXTERNAL_DIR}/zlib"
      "-L${EXTERNAL_DIR}/popt/build/output/src/.libs"
      "-L${EXTERNAL_DIR}/sqlite" "-L${EXTERNAL_DIR}/lua")
  string(JOIN " " RPM_CFLAGS_STR "-fPIC" ${RPM_INC_PATHS} ${RPM_LIB_PATHS})

  if(EXISTS ${EXTERNAL_DIR}/rpm/builddir/librpm.a)
    message(STATUS "Using precompiled RPM library")
    add_custom_target(rpm_external)
  else()
    ExternalProject_Add(
      rpm_external
      SOURCE_DIR ${EXTERNAL_DIR}/rpm
      BINARY_DIR ${EXTERNAL_DIR}/rpm/builddir
      CMAKE_ARGS ""
      CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env "CFLAGS=${RPM_CFLAGS_STR}"
                        CC=gcc cmake ${EXTERNAL_DIR}/rpm
      BUILD_COMMAND ${CMAKE_MAKE_PROGRAM}
      INSTALL_COMMAND ""
      DEPENDS openssl_external zlib_external popt_external ext_sqlite
              lua_external
      BUILD_BYPRODUCTS ${EXTERNAL_DIR}/rpm/builddir/librpm.a)
  endif()

  add_library(ext_rpm STATIC IMPORTED GLOBAL)
  set_target_properties(
    ext_rpm PROPERTIES IMPORTED_LOCATION ${EXTERNAL_DIR}/rpm/builddir/librpm.a)
  add_dependencies(ext_rpm rpm_external)
endif()

# ==============================================================================
# Section 4: Header-only libraries
# ==============================================================================

# nlohmann JSON
add_library(ext_nlohmann INTERFACE)
target_include_directories(ext_nlohmann SYSTEM
                           INTERFACE ${EXTERNAL_DIR}/nlohmann)

# cpp-httplib
add_library(ext_httplib INTERFACE)
target_include_directories(ext_httplib SYSTEM
                           INTERFACE ${EXTERNAL_DIR}/cpp-httplib)

# Header-only libs that are only downloaded for server builds
if(NOT IS_AGENT)
  # rapidjson
  if(EXISTS ${EXTERNAL_DIR}/rapidjson)
    add_library(ext_rapidjson INTERFACE)
    target_include_directories(ext_rapidjson SYSTEM
                               INTERFACE ${EXTERNAL_DIR}/rapidjson/include)
  endif()

  # RxCpp
  if(EXISTS ${EXTERNAL_DIR}/RxCpp)
    add_library(ext_rxcpp INTERFACE)
    target_include_directories(ext_rxcpp SYSTEM
                               INTERFACE ${EXTERNAL_DIR}/RxCpp/Rx/v2/src)
  endif()

  # taskflow
  if(EXISTS ${EXTERNAL_DIR}/taskflow)
    add_library(ext_taskflow INTERFACE)
    target_include_directories(ext_taskflow SYSTEM
                               INTERFACE ${EXTERNAL_DIR}/taskflow)
  endif()

  # concurrentqueue
  if(EXISTS ${EXTERNAL_DIR}/concurrentqueue)
    add_library(ext_concurrentqueue INTERFACE)
    target_include_directories(ext_concurrentqueue SYSTEM
                               INTERFACE ${EXTERNAL_DIR}/concurrentqueue)
  endif()

  # fast_float
  if(EXISTS ${EXTERNAL_DIR}/fast_float)
    add_library(ext_fast_float INTERFACE)
    target_include_directories(ext_fast_float SYSTEM
                               INTERFACE ${EXTERNAL_DIR}/fast_float/include)
  endif()
endif()

# ==============================================================================
# Section 5: libwazuhext — shared library bundling all core external deps
# ==============================================================================

# Create an empty source file so CMake accepts the shared library target. Only
# write if it doesn't exist to avoid triggering rebuilds
if(NOT EXISTS ${CMAKE_CURRENT_BINARY_DIR}/wazuhext_empty.c)
  file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/wazuhext_empty.c "/* empty */\n")
endif()
add_library(wazuhext SHARED ${CMAKE_CURRENT_BINARY_DIR}/wazuhext_empty.c)

# Collect all static libraries that go into libwazuhext (whole-archive)
set(WAZUHEXT_WHOLE_LIBS
    ext_cjson
    ext_zlib
    openssl_ssl
    openssl_crypto
    ext_sqlite
    ext_libyaml
    ext_pcre2)

# Add curl on supported platforms
if(IS_LINUX
   OR IS_DARWIN
   OR IS_WINDOWS)
  list(APPEND WAZUHEXT_WHOLE_LIBS ext_curl)
endif()

# Non-Windows additions
if(NOT IS_WINDOWS)
  list(APPEND WAZUHEXT_WHOLE_LIBS ext_msgpack ext_bzip2)
  if(NOT IS_AGENT)
    list(APPEND WAZUHEXT_WHOLE_LIBS ext_libffi)
  endif()
  if(IS_LINUX)
    list(
      APPEND
      WAZUHEXT_WHOLE_LIBS
      ext_dbus
      ext_lua
      ext_rpm
      ext_popt
      ext_audit
      ext_procps
      ext_libalpm
      ext_libarchive)
  endif()
endif()

# macOS-only
if(IS_DARWIN)
  list(APPEND WAZUHEXT_WHOLE_LIBS ext_libplist)
endif()

# Server-only additions to whole-archive
if(NOT IS_AGENT AND NOT IS_WINDOWS)
  list(APPEND WAZUHEXT_WHOLE_LIBS ext_lzma ext_minizip)
endif()

# --- Platform-specific linking ---

if(IS_DARWIN)
  # macOS: -all_load + install name
  set_target_properties(
    wazuhext
    PROPERTIES INSTALL_RPATH "@rpath"
               BUILD_WITH_INSTALL_RPATH TRUE
               INSTALL_NAME_DIR "@rpath"
               MACOSX_RPATH TRUE)
  target_link_libraries(
    wazuhext
    PRIVATE "-Wl,-all_load" ${WAZUHEXT_WHOLE_LIBS} "-framework Security"
            "-framework CoreFoundation" "-framework SystemConfiguration")

elseif(IS_WINDOWS)
  # Windows (MinGW cross-compile): DLL + delay-import lib
  target_sources(wazuhext PRIVATE ${RESOURCE_OBJ_DLL})
  add_dependencies(wazuhext winpthreadpatched)
  target_link_libraries(
    wazuhext
    PRIVATE -static-libgcc
            "-Wl,--export-all-symbols"
            "-Wl,--add-stdcall-alias"
            "-Wl,-L,${SRC_FOLDER}/build/lib"
            "-Wl,-Bstatic,--whole-archive"
            -lwinpthreadpatched
            ${WAZUHEXT_WHOLE_LIBS}
            "-Wl,--no-whole-archive"
            "-Wl,-Bdynamic"
            -ldelayimp
            wsock32
            ws2_32
            crypt32
            bcrypt)

  # Output .def for delay-import lib creation
  set_target_properties(
    wazuhext
    PROPERTIES LINK_FLAGS
               "-Wl,--output-def,${CMAKE_CURRENT_BINARY_DIR}/libwazuhext.def")

  # Create delay-import library after DLL is built
  add_custom_command(
    TARGET wazuhext
    POST_BUILD
    COMMAND
      i686-w64-mingw32-dlltool -D $<TARGET_FILE:wazuhext> --def
      ${CMAKE_CURRENT_BINARY_DIR}/libwazuhext.def --output-delaylib
      ${SRC_FOLDER}/build/lib/libwazuhext.lib
    COMMENT "Creating delay-import library libwazuhext.lib")

else()
  # Linux: --whole-archive + system libs
  target_link_libraries(
    wazuhext
    PRIVATE "-Wl,--whole-archive"
            ${WAZUHEXT_WHOLE_LIBS}
            "-Wl,--no-whole-archive"
            rt
            dl
            m
            pthread)
endif()

# Output to src/build/lib
set_target_properties(
  wazuhext
  PROPERTIES OUTPUT_NAME "wazuhext"
             PREFIX "lib"
             LIBRARY_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/lib
             RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin
             POSITION_INDEPENDENT_CODE ON)

# Provide include dirs to consumers of wazuhext
target_include_directories(
  wazuhext PUBLIC ${EXTERNAL_DIR}/cJSON ${EXTERNAL_DIR}/openssl/include
                  ${EXTERNAL_DIR}/zlib ${EXTERNAL_DIR}/zlib/contrib)

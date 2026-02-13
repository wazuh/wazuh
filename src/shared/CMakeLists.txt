cmake_minimum_required(VERSION 3.12.4)

project(wazuh C)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
endif()

# Include directories
include_directories(
  ${SRC_FOLDER}/external/audit-userspace/lib
  ${SRC_FOLDER}/external/curl/include/curl/
  ${SRC_FOLDER}/external/libpcre2/include/
  ${SRC_FOLDER}/external/sqlite/
  ${SRC_FOLDER}/external/libyaml/include
  ${SRC_FOLDER}/external/libplist/bin/include/
  ${SRC_FOLDER}/external/bzip2/
  ${SRC_FOLDER}/external/zlib/
  ${SRC_FOLDER}/active-response/include
  ${SRC_FOLDER}/client-agent/include
  ${SRC_FOLDER}/config/include
  ${SRC_FOLDER}/logcollector/include
  ${SRC_FOLDER}/os_auth/include
  ${SRC_FOLDER}/shared_modules/dbsync/include
  ${SRC_FOLDER}/syscheckd/include
  ${SRC_FOLDER}/data_provider/include
  ${SRC_FOLDER}/wazuh_modules/include
  ${SRC_FOLDER}/wazuh_modules/src
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager
  ${SRC_FOLDER}/wazuh_modules/src/task_manager
  ${SRC_FOLDER}/wazuh_db/include
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/error_messages
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/md5
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/sha1
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/sha256
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/md5_sha1_sha256
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/blowfish
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/sha512
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/aes
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/hmac
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/shared
  ${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/signature
  ${CMAKE_CURRENT_SOURCE_DIR}/os_net
  ${CMAKE_CURRENT_SOURCE_DIR}/os_regex
  ${CMAKE_CURRENT_SOURCE_DIR}/os_xml
  ${CMAKE_CURRENT_SOURCE_DIR}/os_zlib)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN32=1 -D_POSIX_C_SOURCE -DPSAPI_VERSION=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

# Collect all source files from the various subdirectories
file(GLOB SHARED_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")

# Remove server-only files that use features not available on Windows
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(
    REMOVE_ITEM
    SHARED_CORE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/batch_queue_op.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/http_op.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/indexed_queue_op.c")
endif()
file(GLOB OS_CRYPTO_BLOWFISH_SRC
     "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/blowfish/*.c")
file(GLOB OS_CRYPTO_MD5_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/md5/*.c")
file(GLOB OS_CRYPTO_SHA1_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/sha1/*.c")
file(GLOB OS_CRYPTO_SHA256_SRC
     "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/sha256/*.c")
file(GLOB OS_CRYPTO_SHA512_SRC
     "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/sha512/*.c")
file(GLOB OS_CRYPTO_AES_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/aes/*.c")
file(GLOB OS_CRYPTO_MD5_SHA1_SHA256_SRC
     "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/md5_sha1_sha256/*.c")
file(GLOB OS_CRYPTO_HMAC_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/hmac/*.c")
file(GLOB OS_CRYPTO_SHARED_SRC
     "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/shared/*.c")
file(GLOB OS_CRYPTO_SIGNATURE_SRC
     "${CMAKE_CURRENT_SOURCE_DIR}/os_crypto/signature/*.c")
file(GLOB OS_NET_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_net/*.c")
file(GLOB OS_REGEX_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_regex/*.c")
file(GLOB OS_XML_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_xml/*.c")
file(GLOB OS_ZLIB_SRC "${CMAKE_CURRENT_SOURCE_DIR}/os_zlib/*.c")

# Active response shared utilities (used by execd and active response binaries)
set(ACTIVE_RESPONSE_SRC "${SRC_FOLDER}/active-response/src/active_responses.c")

# Combine all sources
set(LIBWAZUH_SRC
    ${SHARED_CORE_SRC}
    ${OS_CRYPTO_BLOWFISH_SRC}
    ${OS_CRYPTO_MD5_SRC}
    ${OS_CRYPTO_SHA1_SRC}
    ${OS_CRYPTO_SHA256_SRC}
    ${OS_CRYPTO_SHA512_SRC}
    ${OS_CRYPTO_AES_SRC}
    ${OS_CRYPTO_MD5_SHA1_SHA256_SRC}
    ${OS_CRYPTO_HMAC_SRC}
    ${OS_CRYPTO_SHARED_SRC}
    ${OS_CRYPTO_SIGNATURE_SRC}
    ${OS_NET_SRC}
    ${OS_REGEX_SRC}
    ${OS_XML_SRC}
    ${OS_ZLIB_SRC}
    ${ACTIVE_RESPONSE_SRC})

# Add unit test wrappers if UNIT_TEST is enabled
if(UNIT_TEST)
  # Collect wrapper source files
  file(GLOB WRAPPERS_COMMON_SRC "${SRC_FOLDER}/unit_tests/wrappers/*.c")
  file(GLOB WRAPPERS_EXTERNALS_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/*.c")
  file(GLOB WRAPPERS_EXTERNALS_BZIP2_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/bzip2/*.c")
  file(GLOB WRAPPERS_EXTERNALS_ZLIB_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/zlib/*.c")
  file(GLOB WRAPPERS_EXTERNALS_CJSON_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/cJSON/*.c")
  file(GLOB WRAPPERS_EXTERNALS_OPENSSL_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/openssl/*.c")
  file(GLOB WRAPPERS_EXTERNALS_SQLITE_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/sqlite/*.c")
  file(GLOB WRAPPERS_EXTERNALS_PCRE2_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/externals/pcre2/*.c")
  file(GLOB WRAPPERS_LIBC_SRC "${SRC_FOLDER}/unit_tests/wrappers/libc/*.c")
  file(GLOB WRAPPERS_POSIX_SRC "${SRC_FOLDER}/unit_tests/wrappers/posix/*.c")
  file(GLOB WRAPPERS_WAZUH_SRC "${SRC_FOLDER}/unit_tests/wrappers/wazuh/*.c")
  file(GLOB WRAPPERS_WAZUH_OS_CRYPTO_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_crypto/*.c")
  file(GLOB WRAPPERS_WAZUH_OS_EXECD_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_execd/*.c")
  file(GLOB WRAPPERS_WAZUH_OS_NET_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_net/*.c")
  file(GLOB WRAPPERS_WAZUH_OS_REGEX_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_regex/*.c")
  file(GLOB WRAPPERS_WAZUH_OS_XML_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_xml/*.c")
  file(GLOB WRAPPERS_WAZUH_SHARED_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/*.c")
  file(GLOB WRAPPERS_WAZUH_SYSCHECKD_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/syscheckd/*.c")
  file(GLOB WRAPPERS_WAZUH_WAZUH_DB_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/wazuh_db/*.c")
  file(GLOB WRAPPERS_WAZUH_WAZUH_MODULES_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/wazuh_modules/*.c")
  file(GLOB WRAPPERS_WAZUH_MONITORD_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/monitord/*.c")
  file(GLOB WRAPPERS_WAZUH_OS_AUTH_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_auth/*.c")
  file(GLOB WRAPPERS_WAZUH_ADDAGENT_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/addagent/*.c")
  file(GLOB WRAPPERS_WAZUH_CONFIG_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/config/*.c")
  file(GLOB WRAPPERS_CLIENT_AGENT_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/client-agent/*.c")
  file(GLOB WRAPPERS_WAZUH_REMOTED_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/remoted/*.c")
  file(GLOB WRAPPERS_DATA_PROVIDER_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/data_provider/*.c")
  file(GLOB WRAPPERS_LOGCOLLECTOR_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/logcollector/*.c")
  file(GLOB WRAPPERS_SHARED_MODULES_SRC
       "${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared_modules/*.c")

  # Platform-specific wrappers configuration
  if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    # Windows uses its own wrapper implementations
    file(GLOB WRAPPERS_WINDOWS_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/windows/*.c")
    file(GLOB WRAPPERS_WINDOWS_LIBC_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/windows/libc/*.c")
    file(GLOB WRAPPERS_WINDOWS_POSIX_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/windows/posix/*.c")

    set(UNIT_TEST_WRAPPERS_SRC
        ${WRAPPERS_COMMON_SRC}
        ${WRAPPERS_EXTERNALS_SRC}
        ${WRAPPERS_EXTERNALS_BZIP2_SRC}
        ${WRAPPERS_EXTERNALS_ZLIB_SRC}
        ${WRAPPERS_EXTERNALS_CJSON_SRC}
        ${WRAPPERS_EXTERNALS_OPENSSL_SRC}
        ${WRAPPERS_EXTERNALS_SQLITE_SRC}
        ${WRAPPERS_EXTERNALS_PCRE2_SRC}
        ${WRAPPERS_LIBC_SRC}
        ${WRAPPERS_POSIX_SRC}
        ${WRAPPERS_WAZUH_SRC}
        ${WRAPPERS_WAZUH_OS_CRYPTO_SRC}
        ${WRAPPERS_WAZUH_OS_EXECD_SRC}
        ${WRAPPERS_WAZUH_OS_NET_SRC}
        ${WRAPPERS_WAZUH_OS_REGEX_SRC}
        ${WRAPPERS_WAZUH_OS_XML_SRC}
        ${WRAPPERS_WAZUH_SHARED_SRC}
        ${WRAPPERS_WAZUH_SYSCHECKD_SRC}
        ${WRAPPERS_WAZUH_WAZUH_DB_SRC}
        ${WRAPPERS_WAZUH_WAZUH_MODULES_SRC}
        ${WRAPPERS_WAZUH_MONITORD_SRC}
        ${WRAPPERS_WAZUH_OS_AUTH_SRC}
        ${WRAPPERS_WAZUH_ADDAGENT_SRC}
        ${WRAPPERS_WAZUH_CONFIG_SRC}
        ${WRAPPERS_CLIENT_AGENT_SRC}
        ${WRAPPERS_WAZUH_REMOTED_SRC}
        ${WRAPPERS_DATA_PROVIDER_SRC}
        ${WRAPPERS_LOGCOLLECTOR_SRC}
        ${WRAPPERS_SHARED_MODULES_SRC}
        ${WRAPPERS_WINDOWS_SRC}
        ${WRAPPERS_WINDOWS_LIBC_SRC}
        ${WRAPPERS_WINDOWS_POSIX_SRC})

  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # macOS uses POSIX wrappers with --wrap linker flag
    file(GLOB WRAPPERS_MACOS_SRC "${SRC_FOLDER}/unit_tests/wrappers/macos/*.c")
    file(GLOB WRAPPERS_MACOS_LIBC_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/macos/libc/*.c")
    file(GLOB WRAPPERS_MACOS_POSIX_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/macos/posix/*.c")

    set(UNIT_TEST_WRAPPERS_SRC
        ${WRAPPERS_COMMON_SRC}
        ${WRAPPERS_EXTERNALS_SRC}
        ${WRAPPERS_EXTERNALS_BZIP2_SRC}
        ${WRAPPERS_EXTERNALS_ZLIB_SRC}
        ${WRAPPERS_EXTERNALS_CJSON_SRC}
        ${WRAPPERS_EXTERNALS_OPENSSL_SRC}
        ${WRAPPERS_EXTERNALS_SQLITE_SRC}
        ${WRAPPERS_EXTERNALS_PCRE2_SRC}
        ${WRAPPERS_LIBC_SRC}
        ${WRAPPERS_POSIX_SRC}
        ${WRAPPERS_WAZUH_SRC}
        ${WRAPPERS_WAZUH_OS_CRYPTO_SRC}
        ${WRAPPERS_WAZUH_OS_EXECD_SRC}
        ${WRAPPERS_WAZUH_OS_NET_SRC}
        ${WRAPPERS_WAZUH_OS_REGEX_SRC}
        ${WRAPPERS_WAZUH_OS_XML_SRC}
        ${WRAPPERS_WAZUH_SHARED_SRC}
        ${WRAPPERS_WAZUH_SYSCHECKD_SRC}
        ${WRAPPERS_WAZUH_WAZUH_DB_SRC}
        ${WRAPPERS_WAZUH_WAZUH_MODULES_SRC}
        ${WRAPPERS_WAZUH_MONITORD_SRC}
        ${WRAPPERS_WAZUH_OS_AUTH_SRC}
        ${WRAPPERS_WAZUH_ADDAGENT_SRC}
        ${WRAPPERS_WAZUH_CONFIG_SRC}
        ${WRAPPERS_CLIENT_AGENT_SRC}
        ${WRAPPERS_WAZUH_REMOTED_SRC}
        ${WRAPPERS_DATA_PROVIDER_SRC}
        ${WRAPPERS_LOGCOLLECTOR_SRC}
        ${WRAPPERS_SHARED_MODULES_SRC}
        ${WRAPPERS_MACOS_SRC}
        ${WRAPPERS_MACOS_LIBC_SRC}
        ${WRAPPERS_MACOS_POSIX_SRC})

  else()
    # Linux uses POSIX wrappers with --wrap linker flag
    file(GLOB WRAPPERS_EXTERNALS_AUDIT_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/externals/audit/*.c")
    file(GLOB WRAPPERS_EXTERNALS_PROCPC_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/externals/procpc/*.c")
    file(GLOB WRAPPERS_LINUX_SRC "${SRC_FOLDER}/unit_tests/wrappers/linux/*.c")

    set(UNIT_TEST_WRAPPERS_SRC
        ${WRAPPERS_COMMON_SRC}
        ${WRAPPERS_EXTERNALS_SRC}
        ${WRAPPERS_EXTERNALS_BZIP2_SRC}
        ${WRAPPERS_EXTERNALS_ZLIB_SRC}
        ${WRAPPERS_EXTERNALS_CJSON_SRC}
        ${WRAPPERS_EXTERNALS_OPENSSL_SRC}
        ${WRAPPERS_EXTERNALS_SQLITE_SRC}
        ${WRAPPERS_EXTERNALS_PCRE2_SRC}
        ${WRAPPERS_LIBC_SRC}
        ${WRAPPERS_POSIX_SRC}
        ${WRAPPERS_WAZUH_SRC}
        ${WRAPPERS_WAZUH_OS_CRYPTO_SRC}
        ${WRAPPERS_WAZUH_OS_EXECD_SRC}
        ${WRAPPERS_WAZUH_OS_NET_SRC}
        ${WRAPPERS_WAZUH_OS_REGEX_SRC}
        ${WRAPPERS_WAZUH_OS_XML_SRC}
        ${WRAPPERS_WAZUH_SHARED_SRC}
        ${WRAPPERS_WAZUH_SYSCHECKD_SRC}
        ${WRAPPERS_WAZUH_WAZUH_DB_SRC}
        ${WRAPPERS_WAZUH_WAZUH_MODULES_SRC}
        ${WRAPPERS_WAZUH_MONITORD_SRC}
        ${WRAPPERS_WAZUH_OS_AUTH_SRC}
        ${WRAPPERS_WAZUH_ADDAGENT_SRC}
        ${WRAPPERS_WAZUH_CONFIG_SRC}
        ${WRAPPERS_CLIENT_AGENT_SRC}
        ${WRAPPERS_WAZUH_REMOTED_SRC}
        ${WRAPPERS_DATA_PROVIDER_SRC}
        ${WRAPPERS_LOGCOLLECTOR_SRC}
        ${WRAPPERS_SHARED_MODULES_SRC}
        ${WRAPPERS_EXTERNALS_AUDIT_SRC}
        ${WRAPPERS_EXTERNALS_PROCPC_SRC}
        ${WRAPPERS_LINUX_SRC})
  endif()

endif()

# Create the production wazuh library (without test wrappers)
add_library(wazuh STATIC ${LIBWAZUH_SRC})

# Create a separate test library with wrappers for unit tests only
if(UNIT_TEST)
  add_library(wazuh_test STATIC ${LIBWAZUH_SRC} ${UNIT_TEST_WRAPPERS_SRC})
endif()

# Set properties: library name, output directory
set_target_properties(
  wazuh
  PROPERTIES OUTPUT_NAME "wazuh"
             LINKER_LANGUAGE C
             ARCHIVE_OUTPUT_DIRECTORY ${SRC_FOLDER}
             LIBRARY_OUTPUT_DIRECTORY ${SRC_FOLDER}
             POSITION_INDEPENDENT_CODE ON)

# Add compile definitions
target_compile_definitions(wazuh PRIVATE ARGV0="wazuh")

if(OS_BIG_ENDIAN)
  add_definitions(-DOS_BIG_ENDIAN)
endif(OS_BIG_ENDIAN)

if(CA_NAME)
  target_compile_definitions(wazuh PRIVATE CA_NAME="${CA_NAME}")
endif()

if(IMAGE_TRUST_CHECKS)
  target_compile_definitions(wazuh
                             PRIVATE IMAGE_TRUST_CHECKS=${IMAGE_TRUST_CHECKS})
endif()

if(ENABLE_AUDIT)
  target_compile_definitions(wazuh PRIVATE ENABLE_AUDIT)
endif()

target_link_libraries(wazuh PUBLIC wazuhext)

# Configure wazuh_test library for unit tests
if(UNIT_TEST)
  # Set properties for test library
  set_target_properties(
    wazuh_test
    PROPERTIES OUTPUT_NAME "wazuh_test"
               LINKER_LANGUAGE C
               ARCHIVE_OUTPUT_DIRECTORY ${SRC_FOLDER}
               LIBRARY_OUTPUT_DIRECTORY ${SRC_FOLDER}
               POSITION_INDEPENDENT_CODE ON)

  # Add same compile definitions as production library
  target_compile_definitions(wazuh_test PRIVATE ARGV0="wazuh")
  target_compile_definitions(wazuh_test PRIVATE WAZUH_UNIT_TESTING)

  if(CA_NAME)
    target_compile_definitions(wazuh_test PRIVATE CA_NAME="${CA_NAME}")
  endif()

  if(IMAGE_TRUST_CHECKS)
    target_compile_definitions(wazuh_test
                               PRIVATE IMAGE_TRUST_CHECKS=${IMAGE_TRUST_CHECKS})
  endif()

  if(ENABLE_AUDIT)
    target_compile_definitions(wazuh_test PRIVATE ENABLE_AUDIT)
  endif()

  # Debug flags for unit tests: -g -O0
  target_compile_options(wazuh_test PUBLIC -g -O0)

  # Add coverage libraries and flags for unit tests
  add_coverage_libraries(wazuh_test)

  # Link with wazuhext
  target_link_libraries(wazuh_test PUBLIC wazuhext)
endif()

# Create shared library
if(NOT UNIT_TEST AND NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  if(APPLE)
    # macOS: libwazuhshared.dylib
    add_library(wazuhshared SHARED ${LIBWAZUH_SRC})

    set_target_properties(
      wazuhshared
      PROPERTIES OUTPUT_NAME "wazuhshared"
                 LIBRARY_OUTPUT_DIRECTORY ${SRC_FOLDER}
                 INSTALL_NAME_DIR "@rpath"
                 BUILD_WITH_INSTALL_RPATH TRUE
                 POSITION_INDEPENDENT_CODE ON)

    target_compile_definitions(wazuhshared PRIVATE ARGV0="wazuh")
    # Link with wazuhext (Makefile-built dylib)
    target_link_libraries(wazuhshared PUBLIC wazuhext)

  else()
    # Linux: libwazuhshared.so
    add_library(wazuhshared SHARED ${LIBWAZUH_SRC})

    set_target_properties(
      wazuhshared
      PROPERTIES OUTPUT_NAME "wazuhshared"
                 LIBRARY_OUTPUT_DIRECTORY ${SRC_FOLDER}
                 BUILD_WITH_INSTALL_RPATH TRUE
                 INSTALL_RPATH "$ORIGIN"
                 POSITION_INDEPENDENT_CODE ON)

    target_compile_definitions(wazuhshared PRIVATE ARGV0="wazuh")
    # Link with wazuhext using -Wl,--whole-archive (Linux linker flag)
    target_link_libraries(wazuhshared PUBLIC -Wl,--whole-archive wazuhext
                                             -Wl,--no-whole-archive)
  endif()

  # Apply common compile definitions to shared library (all platforms)
  if(CA_NAME)
    target_compile_definitions(wazuhshared PRIVATE CA_NAME="${CA_NAME}")
  endif()

  if(IMAGE_TRUST_CHECKS)
    target_compile_definitions(wazuhshared
                               PRIVATE IMAGE_TRUST_CHECKS=${IMAGE_TRUST_CHECKS})
  endif()

  if(ENABLE_AUDIT)
    target_compile_definitions(wazuhshared PRIVATE ENABLE_AUDIT)
  endif()
endif()

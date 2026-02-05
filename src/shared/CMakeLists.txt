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
  ${SRC_FOLDER}/client-agent
  ${SRC_FOLDER}/config/include
  ${SRC_FOLDER}/error_messages
  ${SRC_FOLDER}/wazuh_modules/include
  ${SRC_FOLDER}/wazuh_modules/src
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/agent
  ${SRC_FOLDER}/wazuh_modules/src/agent_upgrade/manager
  ${SRC_FOLDER}/wazuh_modules/src/task_manager
  ${CMAKE_CURRENT_SOURCE_DIR}/include
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
  add_definitions(-DWIN32=1)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_definitions(-DDarwin -DHIGHFIRST)
endif()

# Collect all source files from the various subdirectories
file(GLOB SHARED_CORE_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
# Exclude win_shared_stubs.c - only used for libwazuhshared.dll, not libwazuh.a
list(FILTER SHARED_CORE_SRC EXCLUDE REGEX ".*win_shared_stubs\\.c$")
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
    ${OS_ZLIB_SRC})

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
    # Windows uses its own wrapper implementations that don't require --wrap
    # linker flag
    file(GLOB WRAPPERS_WINDOWS_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/windows/*.c")
    file(GLOB WRAPPERS_WINDOWS_LIBC_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/windows/libc/*.c")
    file(GLOB WRAPPERS_WINDOWS_POSIX_SRC
         "${SRC_FOLDER}/unit_tests/wrappers/windows/posix/*.c")

    # Filter out wrappers that use __real_* pattern (require --wrap linker flag)
    set(UNIT_TEST_WRAPPERS_SRC
        ${WRAPPERS_COMMON_SRC}
        ${WRAPPERS_EXTERNALS_BZIP2_SRC}
        ${WRAPPERS_EXTERNALS_ZLIB_SRC}
        ${WRAPPERS_EXTERNALS_CJSON_SRC}
        ${WRAPPERS_EXTERNALS_PCRE2_SRC}
        ${WRAPPERS_WINDOWS_SRC}
        ${WRAPPERS_WINDOWS_LIBC_SRC}
        ${WRAPPERS_WINDOWS_POSIX_SRC}
        ${WRAPPERS_WAZUH_SRC}
        ${WRAPPERS_WAZUH_OS_CRYPTO_SRC}
        ${WRAPPERS_WAZUH_OS_EXECD_SRC}
        ${WRAPPERS_WAZUH_OS_NET_SRC}
        ${WRAPPERS_WAZUH_SYSCHECKD_SRC}
        ${WRAPPERS_WAZUH_WAZUH_DB_SRC}
        ${WRAPPERS_WAZUH_MONITORD_SRC}
        ${WRAPPERS_WAZUH_OS_AUTH_SRC}
        ${WRAPPERS_WAZUH_ADDAGENT_SRC}
        ${WRAPPERS_WAZUH_CONFIG_SRC}
        ${WRAPPERS_CLIENT_AGENT_SRC}
        ${WRAPPERS_WAZUH_REMOTED_SRC}
        ${WRAPPERS_DATA_PROVIDER_SRC}
        ${WRAPPERS_LOGCOLLECTOR_SRC}
        ${WRAPPERS_SHARED_MODULES_SRC})

    # Exclude wrappers that use __real_* pattern (not compatible with Windows
    # without --wrap)
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh/os_regex/os_regex_wrappers\\.c$")
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh/os_xml/os_xml_wrappers\\.c$")
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh/shared/file_op_wrappers\\.c$")
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh/shared/hash_op_wrappers\\.c$")
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh/shared/list_op_wrappers\\.c$")
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh/shared/string_op_wrappers\\.c$")
    list(FILTER UNIT_TEST_WRAPPERS_SRC EXCLUDE REGEX
         ".*/wazuh_modules/wm_agent_upgrade_wrappers\\.c$")
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

  # Add wrapper sources to libwazuh
  list(APPEND LIBWAZUH_SRC ${UNIT_TEST_WRAPPERS_SRC})
endif()

# Create the wazuh library
add_library(wazuh STATIC ${LIBWAZUH_SRC})

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

# Enable WAZUH_UNIT_TESTING to export static functions for unit tests
if(UNIT_TEST)
  target_compile_definitions(wazuh PRIVATE WAZUH_UNIT_TESTING)

  # Debug flags for unit tests: -g -O0
  target_compile_options(wazuh PUBLIC -g -O0)

  # Add coverage libraries and flags for unit tests
  add_coverage_libraries(wazuh)
endif()

target_link_libraries(wazuh PUBLIC wazuhext)

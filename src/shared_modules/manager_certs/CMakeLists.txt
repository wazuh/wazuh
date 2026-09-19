cmake_minimum_required(VERSION 3.12.4)

project(manager_certs CXX)

# Manager-only module (C9/C17/C27): bin/wazuh-manager-certs, the only thing in the product that
# publishes a CA bundle. The commands live in manager_certs_core, as functions over a parsed bundle,
# so the unit tests exercise them in process; main.cpp only resolves the manager home, reads the
# effective configuration and maps outcomes to exit codes. It links ca_bundle -- the same archive
# remoted links inside libremoted_module.so -- so the tool and the daemon can never disagree about
# what a bundle contains or whether it may be vouched for.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

add_library(manager_certs_core STATIC
  src/commands/inspect.cpp
  src/commands/check.cpp
  src/commands/writeLock.cpp
  src/commands/atomicWrite.cpp
  src/commands/add.cpp
  src/commands/remove.cpp
  src/commands/pruneExpired.cpp
  src/commands/stamp.cpp
  src/commands/masterTransport.cpp
  src/commands/fromMaster.cpp)

target_include_directories(manager_certs_core
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${SRC_FOLDER}/external/curl/include)

# PUBLIC: the public header names ca_bundle types (ParsedBundle, X509Ptr), so every consumer needs
# its include directories, and ca_bundle itself carries the vendored libcrypto forward.
target_link_libraries(manager_certs_core PUBLIC ca_bundle)

# --from-master's transport (src/commands/masterTransport.cpp), and nothing more than it needs
# (C38d/P27): `ext_curl` is an IMPORTED STATIC target with no INTERFACE_LINK_LIBRARIES of its own
# (src/external/CMakeLists.txt:357-360), so a consumer has to name curl's own dependencies --
# `ssl`/`crypto` (the GLOBAL aliases of openssl_ssl/openssl_crypto, :106,115) and `ext_zlib` (:157),
# because this leg configures curl --with-openssl --with-zlib (:296-320). Deliberately NOT
# `wazuhext`, which would drag sqlite, yaml, pcre2 and bzip2 into a CLI (task_manager's
# CMakeLists.txt:66-72 is the antipattern), and deliberately not a bare -lcurl either
# (http-request's :70,76-80): this binary must use the vendored 8.20, not the host's.
target_link_libraries(manager_certs_core PRIVATE ext_curl ssl crypto ext_zlib)

# bin/wazuh-manager-certs: inspect / check, and the four writing commands (add / remove /
# prune-expired / stamp); --from-master lands in a later stage. Installed by InstallLocal(), like
# bin/wazuh-manager-conf.
# Built in every mode (also UNIT_TEST) so the CLI end-to-end test can run from the test tree.
add_executable(wazuh-manager-certs src/main.cpp)
target_link_libraries(wazuh-manager-certs PRIVATE manager_certs_core manager_config ext_rapidjson)
if(DEFINED VERSION_FILE)
  target_compile_definitions(wazuh-manager-certs PRIVATE WAZUH_MANAGER_CERTS_VERSION="${VERSION_FILE}")
endif()
set_target_properties(wazuh-manager-certs PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${SRC_FOLDER}/build/bin)
# Same reason as wazuh-manager-conf: an operator runs it on hosts whose system libstdc++ may be
# older than the toolchain's, so the bundled lib/ has to resolve first (src/cmake/WazuhRpath.cmake).
wazuh_set_runtime_rpath(wazuh-manager-certs)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(manager_certs_core)
  add_subdirectory(tests)
endif()

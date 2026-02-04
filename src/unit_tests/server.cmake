# Find the wazuh shared library
find_library(
  WAZUHLIB
  NAMES libwazuh_test.a
  HINTS "${SRC_FOLDER}")
find_library(
  WAZUHEXT
  NAMES libwazuhext.so
  HINTS "${SRC_FOLDER}")
set(uname "Linux")

if(NOT WAZUHLIB)
  message(FATAL_ERROR "libwazuh_test.a not found! Aborting...")
endif()

if(NOT WAZUHEXT)
  message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(
  -ggdb
  -O0
  -g
  -coverage
  -DTEST_SERVER
  -DENABLE_AUDIT
  -DINOTIFY_ENABLED
  -fsanitize=address
  -fsanitize=undefined)
link_libraries(-fsanitize=address -fsanitize=undefined)

# Set tests dependencies - use linker groups to resolve circular dependencies
link_directories("${SRC_FOLDER}/build/lib/")
set(TEST_DEPS
    -Wl,--start-group
    ${WAZUHLIB}
    ${WAZUHEXT}
    -lagent_metadata
    -lrouter
    -lfimebpf
    -lagent_sync_protocol
    -ldbsync
    -lschema_validator
    -lfimdb
    -Wl,--end-group
    -lpthread
    -ldl
    -lcmocka
    -fprofile-arcs
    -ftest-coverage)

add_subdirectory(remoted)
add_subdirectory(wazuh_db)
add_subdirectory(os_auth)
add_subdirectory(os_crypto)
add_subdirectory(wazuh_modules)
add_subdirectory(monitord)
add_subdirectory(os_execd)

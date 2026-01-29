# Find the wazuh shared library
find_library(WAZUHLIB NAMES libwazuh.a HINTS "${SRC_FOLDER}")
find_library(WAZUHEXT NAMES libwazuhext.dylib HINTS "${SRC_FOLDER}")
if(WAZUHEXT)
  set(uname "Darwin")
else()
  set(uname "Linux")
endif()
find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")

if(NOT WAZUHLIB)
    message(FATAL_ERROR "libwazuh.a not found! Aborting...")
endif()

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags and set tests dependencies
link_directories("${SRC_FOLDER}/build/lib/")
if(${uname} STREQUAL "Darwin")
    set(TEST_DEPS
        -Wl,-all_load
        ${WAZUHLIB} ${WAZUHEXT}
        -lagent_metadata -lagent_sync_protocol -ldbsync -lschema_validator -lfimdb
        -Wl,-noall_load
        -lpthread -ldl -fprofile-arcs -ftest-coverage)
    add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -I/usr/local/include -DENABLE_SYSC -DWAZUH_UNIT_TESTING)
else()
    add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -DENABLE_AUDIT -DINOTIFY_ENABLED -fsanitize=address -fsanitize=undefined)
    link_libraries(-fsanitize=address -fsanitize=undefined)
    set(TEST_DEPS
        -Wl,--start-group
        ${WAZUHLIB} ${WAZUHEXT}
        -lagent_metadata -lfimebpf -lagent_sync_protocol -ldbsync -lschema_validator -lfimdb
        -Wl,--end-group
        -lpthread -lcmocka -ldl -fprofile-arcs -ftest-coverage)
endif()

if(NOT ${uname} STREQUAL "Darwin")
  add_subdirectory(client-agent)
  add_subdirectory(logcollector)
  add_subdirectory(os_execd)
endif()

add_subdirectory(wazuh_modules)

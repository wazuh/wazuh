# Find the wazuh shared library
if(${OS} STREQUAL "mac")
  find_library(WAZUHEXT NAMES libwazuhext.dylib HINTS "${SRC_FOLDER}")
else()
  find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")
endif()

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -DENABLE_AUDIT -DINOTIFY_ENABLED)

# Set tests dependencies
if(${OS} STREQUAL "mac")
    set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lpthread -lcmocka -I/usr/local/include/cmocka.h -fprofile-arcs -ftest-coverage)
else()
    set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lpthread -lcmocka -fprofile-arcs -ftest-coverage)
endif()

add_subdirectory(client-agent)
add_subdirectory(wazuh_modules)

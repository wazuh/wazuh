# Find the wazuh shared library
if(${TARGET} STREQUAL "mac")
  find_library(WAZUHEXT NAMES libwazuhext.dylib HINTS "${SRC_FOLDER}")
else()
  find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")
endif()

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# # Add compiling flags and set tests dependencies
if(${TARGET} STREQUAL "mac")
    set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lpthread -fprofile-arcs -ftest-coverage)
    add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -DENABLE_AUDIT -DINOTIFY_ENABLED -I/usr/local/include)
else()
    add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -DENABLE_AUDIT -DINOTIFY_ENABLED)
    set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lpthread -lcmocka -fprofile-arcs -ftest-coverage)
endif()

add_subdirectory(client-agent)
add_subdirectory(wazuh_modules)

# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT)

# Set tests dependencies
set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lcmocka -fprofile-arcs -ftest-coverage)

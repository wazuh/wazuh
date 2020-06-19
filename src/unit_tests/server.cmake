# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_SERVER -DENABLE_AUDIT -DINOTIFY_ENABLED)

# Set tests dependencies
set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lpthread -lcmocka -fprofile-arcs -ftest-coverage)

add_subdirectory(analysisd)
add_subdirectory(wazuh_db)
add_subdirectory(wazuh_modules)
add_subdirectory(wazuh_modules/gcp)
add_subdirectory(wazuh_modules/scheduling)
add_subdirectory(wazuh_modules/vulnerability_detector)

# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")
set(uname "Linux")

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags
add_compile_options(-ggdb -O0 -g -coverage -DTEST_SERVER -DENABLE_AUDIT -DINOTIFY_ENABLED -fsanitize=address -fsanitize=undefined)
link_libraries(-fsanitize=address -fsanitize=undefined)
# Set tests dependencies
link_directories("${SRC_FOLDER}/syscheckd/build/lib/")
set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lpthread -ldl -lfimebpf -lcmocka -fprofile-arcs -ftest-coverage)

add_subdirectory(remoted)
add_subdirectory(wazuh_db)
add_subdirectory(os_auth)
add_subdirectory(os_crypto)
add_subdirectory(wazuh_modules)
add_subdirectory(monitord)
add_subdirectory(logcollector)
add_subdirectory(os_execd)
add_subdirectory(os_integrator)
add_subdirectory(addagent)
add_subdirectory(os_maild)
add_subdirectory(os_csyslogd)

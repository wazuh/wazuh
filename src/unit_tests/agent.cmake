# Find the wazuh shared library
find_library(WAZUHEXT NAMES libwazuhext.dylib HINTS "${SRC_FOLDER}")
if(WAZUHEXT)
  set(uname "Darwin")
else()
  set(uname "Linux")
endif()
find_library(WAZUHEXT NAMES libwazuhext.so HINTS "${SRC_FOLDER}")

if(NOT WAZUHEXT)
    message(FATAL_ERROR "libwazuhext not found! Aborting...")
endif()

# Add compiling flags and set tests dependencies
if(${uname} STREQUAL "Darwin")
    link_directories("${SRC_FOLDER}/shared_modules/agent_metadata/build/lib/")
    set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lagent_metadata -lpthread -ldl -fprofile-arcs -ftest-coverage)
    add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -I/usr/local/include -DENABLE_SYSC -DWAZUH_UNIT_TESTING)
else()
    link_directories("${SRC_FOLDER}/syscheckd/build/lib/")
    link_directories("${SRC_FOLDER}/shared_modules/agent_metadata/build/lib/")
    add_compile_options(-ggdb -O0 -g -coverage -DTEST_AGENT -DENABLE_AUDIT -DINOTIFY_ENABLED -fsanitize=address -fsanitize=undefined)
    link_libraries(-fsanitize=address -fsanitize=undefined)
    set(TEST_DEPS ${WAZUHLIB} ${WAZUHEXT} -lagent_metadata -lpthread -lcmocka -ldl -lfimebpf -fprofile-arcs -ftest-coverage)
endif()

if(NOT ${uname} STREQUAL "Darwin")
  add_subdirectory(client-agent)
  add_subdirectory(logcollector)
  add_subdirectory(os_execd)
endif()

add_subdirectory(wazuh_modules)

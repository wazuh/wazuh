# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND wmdb_tests_names "test_wm_database")
list(APPEND wmdb_tests_flags "-Wl,--wrap,wdb_set_agent_groups -Wl,--wrap,opendir -Wl,--wrap,readdir -Wl,--wrap,strerror -Wl,--wrap,unlink \
                              -Wl,--wrap,closedir -Wl,--wrap,rmdir_ex -Wl,--wrap,getpid  -Wl,--wrap,w_is_single_node -Wl,--wrap,_mterror \
                              -Wl,--wrap,wdb_get_all_agents_rbtree -Wl,--wrap,rbtree_get -Wl,--wrap,wdb_get_agent_group -Wl,--wrap,OS_CIDRtoStr \
                              -Wl,--wrap,wdb_insert_agent -Wl,--wrap,rbtree_keys -Wl,--wrap,OS_IsAllowedID -Wl,--wrap,wdb_get_agent_name \
                              -Wl,--wrap,wdb_remove_agent -Wl,--wrap,fopen -Wl,--wrap,wfopen \
                              -Wl,--wrap,wdb_get_agent_name -Wl,--wrap,wdbc_query_ex -Wl,--wrap,popen -Wl,--wrap,so_get_module_handle \
                              ${DEBUG_OP_WRAPPERS} ${STDIO_OP_WRAPPERS}")

# Add extra compiling flags
add_compile_options(-Wall)

# Generate database library with wazuh_modules objects
file(GLOB_RECURSE wm_database_objects ../../../build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*.c.o)
list(REMOVE_ITEM wm_database_objects ../../../build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main.c.o)

add_library(WM_DATABASE_O STATIC ${wm_database_objects})

set_source_files_properties(
  ${wm_database_objects}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
)

set_target_properties(
  WM_DATABASE_O
  PROPERTIES
  LINKER_LANGUAGE C
)

# Compilig tests
list(LENGTH wmdb_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET wmdb_tests_names ${counter} test_name)
    list(GET wmdb_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        WM_DATABASE_O
        ${TEST_DEPS}
    )
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

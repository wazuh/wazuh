# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

# Tests list and flags
list(APPEND tests_names "test_wm_container_images")
list(APPEND tests_flags "-Wl,--wrap=_mwarn,--wrap=_minfo,--wrap=_merror \
                         -Wl,--wrap=_mtwarn,--wrap=_mtinfo,--wrap=_mterror,--wrap=_mtdebug1,--wrap=_mtdebug2")
list(APPEND use_shared_libs 1)

list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.h")
list(APPEND shared_libs "../scheduling/wmodules_scheduling_helpers.c")

# Generate wazuh modules library
file(GLOB_RECURSE container_images ../../../build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/*.c.o)
list(REMOVE_ITEM container_images ../../../build/wazuh_modules/CMakeFiles/wazuh_modulesd_lib.dir/src/main.c.o)

add_library(CONTAINER_IMAGES_O STATIC ${container_images})

set_source_files_properties(
  ${container_images}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  CONTAINER_IMAGES_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(CONTAINER_IMAGES_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Compiling tests
list(LENGTH tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET tests_names ${counter} test_name)
    list(GET tests_flags ${counter} test_flags)
    list(GET use_shared_libs ${counter} use_libs)

    if(use_libs EQUAL "1")
      add_executable(${test_name} ${test_name}.c ${shared_libs})
    else ()
      add_executable(${test_name} ${test_name}.c)
    endif()

    if(NOT APPLE)
        target_link_libraries(
            ${test_name}
            -Wl,--start-group
            ${WAZUHLIB}
            ${WAZUHEXT}
            CONTAINER_IMAGES_O
            -Wl,--end-group
            -lcmocka
            -ldl
            -fprofile-arcs
            -ftest-coverage
        )
    else()
        target_link_libraries(
            ${test_name}
            ${WAZUHLIB}
            ${WAZUHEXT}
            CONTAINER_IMAGES_O
            -lcmocka
            -fprofile-arcs
            -ftest-coverage
        )
    endif()
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(${test_name} ${test_name})
endforeach()

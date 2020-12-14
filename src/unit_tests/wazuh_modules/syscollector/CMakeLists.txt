# Generate syscollector library
file(GLOB syscollector_files
    ${SRC_FOLDER}/wazuh_modules/*.o
    ${SRC_FOLDER}/wazuh_modules/syscollector/*.o)
list(REMOVE_ITEM syscollector_files ${SRC_FOLDER}/wazuh_modules/main.o)

add_library(SYSCOLLECTOR_O STATIC ${syscollector_files})

set_source_files_properties(
  ${syscollector_files}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
)

set_target_properties(
  SYSCOLLECTOR_O
  PROPERTIES
  LINKER_LANGUAGE C
)

target_link_libraries(SYSCOLLECTOR_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate syscollector tests
list(APPEND syscollector_names "test_syscollector_common")
list(APPEND syscollector_flags "-Wl,--wrap,_minfo -Wl,--wrap,_merror -Wl,--wrap,_mwarn -Wl,--wrap,rbtree_insert -Wl,--wrap,rbtree_replace \
                                -Wl,--wrap,rbtree_delete -Wl,--wrap,rbtree_get -Wl,--wrap,rbtree_keys -Wl,--wrap,w_get_timestamp -Wl,--wrap,wm_sendmsg")

# Compiling tests
list(LENGTH syscollector_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET syscollector_names ${counter} test_name)
    list(GET syscollector_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        SYSCOLLECTOR_O
        ${TEST_DEPS}
    )
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(${test_name} ${test_name})
endforeach()

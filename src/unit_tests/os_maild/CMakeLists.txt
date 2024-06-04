# Generate os_maild library
file(GLOB os_maild_files
    ${SRC_FOLDER}/os_maild/*.o)
list(REMOVE_ITEM os_maild_files ${SRC_FOLDER}/os_maild/maild.o)

add_library(OS_MAILD_O STATIC ${os_maild_files})

set_source_files_properties(
    ${os_maild_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_MAILD_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_MAILD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate tests
list(APPEND os_maild_names "test_printtable")
list(APPEND os_maild_flags "${DEBUG_OP_WRAPPERS}")

list(LENGTH os_maild_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_maild_names ${counter} os_maild_test_name)
    list(GET os_maild_flags ${counter} os_maild_test_flags)

    add_executable(${os_maild_test_name} ${os_maild_test_name}.c)

    target_link_libraries(
        ${os_maild_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_MAILD_O
        ${TEST_DEPS}
    )

    if(NOT os_maild_test_flags STREQUAL " ")
        target_link_libraries(
            ${os_maild_test_name}
            ${os_maild_test_flags}
        )
    endif()
    add_test(NAME ${os_maild_test_name} COMMAND ${os_maild_test_name})
endforeach()

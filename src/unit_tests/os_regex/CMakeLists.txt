# Generate os_regex library
file(GLOB os_regex_files
    ${SRC_FOLDER}/os_regex/*.o)

add_library(OS_REGEX_O STATIC ${os_regex_files})

set_source_files_properties(
    ${os_regex_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_REGEX_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_REGEX_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate os_regex tests
list(APPEND os_regex_names "test_os_regex")
list(APPEND os_regex_flags " ")

# OS_Regex execute, regex_matching
list(APPEND os_regex_names "test_os_regex_execute")
list(APPEND os_regex_flags " ")

# Compiling tests
list(LENGTH os_regex_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_regex_names ${counter} test_name)
    list(GET os_regex_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_REGEX_O
        ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

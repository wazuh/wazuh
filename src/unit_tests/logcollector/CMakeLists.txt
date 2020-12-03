# Generate logcollector library
file(GLOB logcollector_files
    ${SRC_FOLDER}/logcollector/*.o)
add_library(LOGCOLLECTOR_O STATIC ${logcollector_files})
set_source_files_properties(
    ${logcollector_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)
set_target_properties(
    LOGCOLLECTOR_O
    PROPERTIES
    LINKER_LANGUAGE C
)
target_link_libraries(LOGCOLLECTOR_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)
# Generate logcollector tests
list(APPEND logcollector_names "test_logcollector")
list(APPEND logcollector_flags "-Wl,--wrap,OSHash_Get_ex -Wl,--wrap,OSHash_Get_ex")

list(LENGTH logcollector_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET logcollector_names ${counter} logcollector_test_name)
    list(GET logcollector_flags ${counter} logcollector_test_flags)
    add_executable(${logcollector_test_name} ${logcollector_test_name}.c)
    target_link_libraries(
        ${logcollector_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        LOGCOLLECTOR_O
        ${TEST_DEPS}
    )
    if(NOT logcollector_test_flags STREQUAL " ")
        target_link_libraries(
            ${logcollector_test_name}
            ${logcollector_test_flags}
        )
    endif()
    add_test(NAME ${logcollector_test_name} COMMAND ${logcollector_test_name})
endforeach()

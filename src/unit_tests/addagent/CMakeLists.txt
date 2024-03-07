# Generate addagent library
file(GLOB addagent_files
    ${SRC_FOLDER}/addagent/*.o)

list(REMOVE_ITEM addagent_files ${SRC_FOLDER}/addagent/main.o)

add_library(ADDAGENT_O STATIC ${addagent_files})

set_source_files_properties(
    ${addagent_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    ADDAGENT_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(ADDAGENT_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND addagent_names "test_manage_keys")
list(APPEND addagent_flags "${DEBUG_OP_WRAPPERS} ${STDIO_OP_WRAPPERS} \
                            -Wl,--wrap,mkstemp_ex \
                            -Wl,--wrap,stat -Wl,--wrap,chmod -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fprintf -Wl,--wrap,fgets -Wl,--wrap,rename_ex\
                            -Wl,--wrap,encode_base64 -Wl,--wrap,decode_base64 -Wl,--wrap,wfopen -Wl,--wrap,popen")

list(LENGTH addagent_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET addagent_names ${counter} addagent_test_name)
    list(GET addagent_flags ${counter} addagent_test_flags)

    add_executable(${addagent_test_name} ${addagent_test_name}.c)

    target_link_libraries(
        ${addagent_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        ADDAGENT_O
        ${TEST_DEPS}
    )
    if(NOT addagent_test_flags STREQUAL " ")
        target_link_libraries(
            ${addagent_test_name}
            ${addagent_test_flags}
        )
    endif()
    add_test(NAME ${addagent_test_name} COMMAND ${addagent_test_name})
endforeach()

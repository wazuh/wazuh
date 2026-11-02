file(GLOB agentlessd_files ${SRC_FOLDER}/agentlessd/*.o)
list(REMOVE_ITEM agentlessd_files ${SRC_FOLDER}/agentlessd/main.o)

add_library(AGENTLESSD_O STATIC ${agentlessd_files})

set_source_files_properties(
    ${agentlessd_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    AGENTLESSD_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(AGENTLESSD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate tests
list(APPEND agentlessd_names "test_lessdcom")
list(APPEND agentlessd_flags "-Wl,--wrap,close -Wl,--wrap,accept -Wl,--wrap,select -Wl,--wrap,FOREVER \
                              -Wl,--wrap,OS_BindUnixDomain -Wl,--wrap,OS_RecvSecureTCP \
                              -Wl,--wrap,OS_SendSecureTCP ${DEBUG_OP_WRAPPERS}")

# Compiling tests
list(LENGTH agentlessd_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET agentlessd_names ${counter} agentlessd_test_name)
    list(GET agentlessd_flags ${counter} agentlessd_test_flags)

    add_executable(${agentlessd_test_name} ${agentlessd_test_name}.c)

    target_link_libraries(
        ${agentlessd_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        AGENTLESSD_O
        ${TEST_DEPS}
    )

    if(NOT agentlessd_test_flags STREQUAL " ")
        target_link_libraries(
            ${agentlessd_test_name}
            ${agentlessd_test_flags}
        )
    endif()
    add_test(NAME ${agentlessd_test_name} COMMAND ${agentlessd_test_name})
endforeach()

# Generate fluentd_forwarder library
file(GLOB fluentd_forwarder_files
    ${SRC_FOLDER}/wazuh_modules/*.o)

add_library(FLUENTD_FORWARDER_O STATIC ${fluentd_forwarder_files})

set_source_files_properties(
    ${fluentd_forwarder_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    FLUENTD_FORWARDER_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(FLUENTD_FORWARDER_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate fluentd_forwarder tests
list(APPEND fluentd_forwarder_names "test_fluentd_forwarder")
list(APPEND fluentd_forwarder_flags "-Wl,--wrap,time -Wl,--wrap,OS_SendUnix -Wl,--wrap,OS_ConnectUnixDomain -Wl,--wrap,OS_ConnectTCP ${DEBUG_OP_WRAPPERS}")

# Compiling tests
list(LENGTH fluentd_forwarder_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET fluentd_forwarder_names ${counter} test_name)
    list(GET fluentd_forwarder_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        FLUENTD_FORWARDER_O
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

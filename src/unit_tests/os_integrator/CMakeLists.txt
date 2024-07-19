# Generate os_integrator library
file(GLOB os_integrator_files
    ${SRC_FOLDER}/os_integrator/*.o)

add_library(OS_INTEGRATOR_O STATIC ${os_integrator_files})

set_source_files_properties(
    ${os_integrator_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_INTEGRATOR_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_INTEGRATOR_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

list(APPEND os_integrator_names "test_integrator")
list(APPEND os_integrator_flags "-Wl,--wrap,jqueue_open -Wl,--wrap,jqueue_next -Wl,--wrap,FOREVER -Wl,--wrap,time ${DEBUG_OP_WRAPPERS} \
                                 -Wl,--wrap,os_random -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,fprintf -Wl,--wrap,unlink,--wrap,getpid \
                                 -Wl,--wrap,File_DateofChange -Wl,--wrap,wfopen -Wl,--wrap,popen ${STDIO_OP_WRAPPERS}")

list(LENGTH os_integrator_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_integrator_names ${counter} os_integrator_test_name)
    list(GET os_integrator_flags ${counter} os_integrator_test_flags)

    add_executable(${os_integrator_test_name} ${os_integrator_test_name}.c)

    target_link_libraries(
        ${os_integrator_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_INTEGRATOR_O
        ${TEST_DEPS}
    )
    if(NOT os_integrator_test_flags STREQUAL " ")
        target_link_libraries(
            ${os_integrator_test_name}
            ${os_integrator_test_flags}
        )
    endif()
    add_test(NAME ${os_integrator_test_name} COMMAND ${os_integrator_test_name})
endforeach()

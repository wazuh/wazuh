# Generate os_net library
file(GLOB os_net_files
    ${SRC_FOLDER}/os_net/*.o)

add_library(OS_NET_O STATIC ${os_net_files})

set_source_files_properties(
    ${os_net_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    OS_NET_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(OS_NET_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate os_net tests
list(APPEND os_net_names "test_os_net")
list(APPEND os_net_flags "-Wl,--wrap,socket -Wl,--wrap,listen -Wl,--wrap,bind -Wl,--wrap,setsockopt \
                          -Wl,--wrap,getsockopt -Wl,--wrap,connect -Wl,--wrap,accept -Wl,--wrap,send \
                          -Wl,--wrap,recv -Wl,--wrap,recvfrom -Wl,--wrap,chmod -Wl,--wrap,chown -Wl,--wrap,getuid -Wl,--wrap,getgid -Wl,--wrap,stat -Wl,--wrap,fcntl \
                          -Wl,--wrap,getaddrinfo -Wl,--wrap,OS_IsValidIP -Wl,--wrap,OS_GetIPv4FromIPv6 -Wl,--wrap,OS_ExpandIPv6 \
                          -Wl,--wrap,sleep -Wl,--wrap,getpid ${DEBUG_OP_WRAPPERS}")

# Compiling tests
list(LENGTH os_net_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_net_names ${counter} test_name)
    list(GET os_net_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_NET_O
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

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

list(APPEND os_net_names "test_os_net")
list(APPEND os_net_flags "-Wl,--wrap,bind -Wl,--wrap,socket -Wl,--wrap,setsockopt -Wl,--wrap,listen -Wl,--wrap,close -Wl,--wrap,getpid")

list(LENGTH os_net_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_net_names ${counter} os_net_test_name)
    list(GET os_net_flags ${counter} os_net_test_flags)

    add_executable(${os_net_test_name} ${os_net_test_name}.c)

    target_link_libraries(
        ${os_net_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        OS_NET_O
        ${TEST_DEPS}
    )

    if(NOT os_net_test_flags STREQUAL " ")
        target_link_libraries(
            ${os_net_test_name}
            ${os_net_test_flags}
        )
    endif()
    add_test(NAME ${os_net_test_name} COMMAND ${os_net_test_name})
endforeach()

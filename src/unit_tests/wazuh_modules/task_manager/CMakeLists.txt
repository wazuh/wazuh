# Generate task manager library
file(GLOB task_files
    ${SRC_FOLDER}/wazuh_modules/*.o
    ${SRC_FOLDER}/wazuh_modules/task_manager/*.o)
list(REMOVE_ITEM task_files ${SRC_FOLDER}/wazuh_modules/main.o)

add_library(TASK_O STATIC ${task_files})

set_source_files_properties(
    ${task_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    TASK_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(TASK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate task manager tests
list(APPEND task_names "test_wm_task_manager")
list(APPEND task_flags "-Wl,--wrap,pthread_exit -Wl,--wrap,CreateThread -Wl,--wrap,OS_BindUnixDomainWithPerms -Wl,--wrap,select -Wl,--wrap,close \
                        -Wl,--wrap,accept -Wl,--wrap,OS_RecvSecureTCP -Wl,--wrap,OS_SendSecureTCP -Wl,--wrap,w_is_worker -Wl,--wrap,wm_task_manager_parse_message -Wl,--wrap,wm_task_manager_process_task \
                        -Wl,--wrap,wm_task_manager_parse_data_response -Wl,--wrap,getpid ${DEBUG_OP_WRAPPERS}")

list(APPEND task_names "test_wm_task_manager_parsing")
list(APPEND task_flags "-Wl,--wrap,w_get_timestamp ${DEBUG_OP_WRAPPERS}")

list(APPEND task_names "test_wm_task_manager_commands")
list(APPEND task_flags "-Wl,--wrap,wm_task_manager_parse_data_response -Wl,--wrap,wm_task_manager_parse_data_result \
                        -Wl,--wrap,wdbc_query_ex -Wl,--wrap,wdbc_parse_result -Wl,--wrap,time -Wl,--wrap,w_sleep_until \
                        ${DEBUG_OP_WRAPPERS}")

# Compilig tests
list(LENGTH task_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET task_names ${counter} test_name)
    list(GET task_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
        ${test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        TASK_O
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

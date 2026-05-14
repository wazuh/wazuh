# Generate win32 library
file(GLOB win32_files
    ${SRC_FOLDER}/win32/*.o)

list(REMOVE_ITEM win32_files ${SRC_FOLDER}/win32/main.o)

#${SRC_FOLDER}/monitord/*.o

add_library(WIN32 STATIC ${win32_files})

set_source_files_properties(
    ${win32_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    WIN32
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(WIN32 ${WAZUHLIB} ${WAZUHEXT} -lpthread)
link_directories(${SRC_FOLDER}/syscheckd/build/bin)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate win32 tests
list(APPEND win32_names "test_win_utils")
list(APPEND win32_flags "-Wl,--wrap,cJSON_GetObjectItem -Wl,--wrap,cJSON_GetArraySize -Wl,--wrap,send_msg \
                        -Wl,--wrap,cJSON_GetArrayItem -Wl,--wrap,cJSON_GetStringValue -Wl,--wrap,time \
                        -Wl,--wrap,fim_sync_push_msg -Wl,--wrap,fim_run_integrity -Wl,--wrap,fim_db_remove_path \
                        -Wl,--wrap=syscom_dispatch -Wl,--wrap=Start_win32_Syscheck \ -Wl,--wrap=is_fim_shutdown \
                        -Wl,--wrap=_imp__dbsync_initialize -Wl,--wrap=_imp__rsync_initialize -Wl,--wrap=fim_db_teardown \
                        -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_transaction_start -Wl,--wrap,fim_db_transaction_deleted_rows \
                        -Wl,--wrap,fim_db_transaction_sync_row -Wl,--wrap,fim_db_file_update -Wl,--wrap,fim_db_file_pattern_search \
                        -Wl,--wrap,fim_db_init ${DEBUG_OP_WRAPPERS}")

list(LENGTH win32_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET win32_names ${counter} win32_test_name)
    list(GET win32_flags ${counter} win32_test_flags)

    add_executable(${win32_test_name} ${win32_test_name}.c)

    target_link_libraries(
        ${win32_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        WIN32
        ${TEST_DEPS}
        fimdb
    )

    if(NOT win32_test_flags STREQUAL " ")
        target_link_libraries(
            ${win32_test_name}
            ${win32_test_flags}
        )
    endif()
    add_test(NAME ${win32_test_name} COMMAND ${win32_test_name})
endforeach()

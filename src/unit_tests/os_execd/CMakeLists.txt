# Generate execd library
file(GLOB execd_files
    ${SRC_FOLDER}/os_execd/*.o)

add_library(EXECD_O STATIC ${execd_files})

set_source_files_properties(
    ${execd_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    EXECD_O
    PROPERTIES
    LINKER_LANGUAGE C
)

target_link_libraries(EXECD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Generate Execd tests
if(${TARGET} STREQUAL "winagent")
    list(APPEND execd_names "test_win_execd")
    list(APPEND execd_flags "-Wl,--wrap,_mtdebug1 -Wl,--wrap,_mterror \
                             -Wl,--wrap,read_exec_config -Wl,--wrap,get_command_by_name -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,fwrite \
                             -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek \
                             -Wl,--wrap,remove -Wl,--wrap,fgetpos -Wl,--wrap=fgetc")
else()
    list(APPEND execd_names "test_execd")
    list(APPEND execd_flags "-Wl,--wrap,_mtdebug1 -Wl,--wrap,_mtdebug2 -Wl,--wrap,_mterror -Wl,--wrap,time -Wl,--wrap,select -Wl,--wrap,OS_RecvUnix \
                             -Wl,--wrap,read_exec_config -Wl,--wrap,get_command_by_name -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,fwrite \
                             -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fflush -Wl,--wrap,fgets -Wl,--wrap,fread -Wl,--wrap,fseek -Wl,--wrap,CreateThreadJoinable \
                             -Wl,--wrap,remove -Wl,--wrap,fgetpos -Wl,--wrap=fgetc")
endif()

list(LENGTH execd_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET execd_names ${counter} execd_test_name)
    list(GET execd_flags ${counter} execd_test_flags)

    add_executable(${execd_test_name} ${execd_test_name}.c)

    target_link_libraries(
        ${execd_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        EXECD_O
        ${TEST_DEPS}
    )

    if(NOT execd_test_flags STREQUAL " ")
        target_link_libraries(
            ${execd_test_name}
            ${execd_test_flags}
        )
    endif()
    add_test(NAME ${execd_test_name} COMMAND ${execd_test_name})
endforeach()

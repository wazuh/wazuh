
file(GLOB os_csyslogd_files ${SRC_FOLDER}/os_csyslogd/*.o)
list(REMOVE_ITEM os_csyslogd_files ${SRC_FOLDER}/os_csyslogd/main.o)


add_library(CSYSLOGD_O STATIC ${os_csyslogd_files})

set_source_files_properties(
    ${os_csyslogd_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
)

set_target_properties(
    CSYSLOGD_O
    PROPERTIES
    LINKER_LANGUAGE C
  )

target_link_libraries(CSYSLOGD_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)


# Generate tests src/unit_tests/csyslogd/test_csyslogd.c
list(APPEND os_csyslogd_names "test_csyslogd")
list(APPEND os_csyslogd_flags "-Wl,--wrap,jqueue_open -Wl,--wrap,jqueue_next -Wl,--wrap,FOREVER -Wl,--wrap,time ${DEBUG_OP_WRAPPERS} \
                                 -Wl,--wrap,os_random -Wl,--wrap,wpopenv -Wl,--wrap,wpclose -Wl,--wrap,fprintf -Wl,--wrap,File_DateofChange ${STDIO_OP_WRAPPERS} \
                                 -Wl,--wrap,merror -Wl,--wrap,minfo -Wl,--wrap,mdebug1 -Wl,--wrap,mdebug2 -Wl,--wrap,merror -Wl,--wrap,wfopen \
                                 -Wl,--wrap,w_ftell -Wl,--wrap,fgets -Wl,--wrap,OS_Alert_SendSyslog_JSON -Wl,--wrap,OS_Alert_SendSyslog\
                                 -Wl,--wrap,OS_IsValidIP -Wl,--wrap,OS_ConnectUDP -Wl,--wrap,time -Wl,--wrap,Read_FileMon -Wl,--wrap,Init_FileQueue -Wl,--wrap,sleep \
                                 -Wl,--wrap,popen")

# Compiling tests
list(LENGTH os_csyslogd_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_csyslogd_names ${counter} csyslogd_test_name)
    list(GET os_csyslogd_flags ${counter} csyslogd_test_flags)

    add_executable(${csyslogd_test_name} ${csyslogd_test_name}.c)

    target_link_libraries(
        ${csyslogd_test_name}
        ${WAZUHLIB}
        ${WAZUHEXT}
        CSYSLOGD_O
        ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${csyslogd_test_name}
            ${csyslogd_test_flags}
        )
    endif()
    add_test(NAME ${csyslogd_test_name} COMMAND ${csyslogd_test_name})
endforeach()

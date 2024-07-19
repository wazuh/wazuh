#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate msgs tests
list(APPEND os_crypto_shared_tests_names "test_msgs")
list(APPEND os_crypto_shared_tests_flags "-Wl,--wrap,merror_exit -Wl,--wrap,linked_queue_push_ex -Wl,--wrap,fprintf -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,remove \
                            -Wl,--wrap,sleep -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek -Wl,--wrap,wfopen \
                            -Wl,--wrap,stat -Wl,--wrap,getpid -Wl,--wrap=key_lock_write -Wl,--wrap=key_unlock -Wl,--wrap=time \
                            -Wl,--wrap,fgetpos -Wl,--wrap=fgetc -Wl,--wrap,popen ${DEBUG_OP_WRAPPERS}")

# Generate keys tests
list(APPEND os_crypto_shared_tests_names "test_keys")
list(APPEND os_crypto_shared_tests_flags "-Wl,--wrap,rbtree_get \
                                -Wl,--wrap,fopen,--wrap,fclose,--wrap,fflush,--wrap,fgets,--wrap,fgetpos,--wrap,fread,--wrap,fseek,--wrap,fwrite,--wrap,remove,--wrap,fgetc,--wrap,fprintf \
                                -Wl,--wrap,TempFile,--wrap,OS_MoveFile -Wl,--wrap,_merror -Wl,--wrap,wfopen \
                                -Wl,--wrap,_mdebug2 -Wl,--wrap,unlink,--wrap,getpid -Wl,--wrap,OS_IsValidIP -Wl,--wrap,popen")

# Compiling tests
list(LENGTH os_crypto_shared_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET os_crypto_shared_tests_names ${counter} test_name)
    list(GET os_crypto_shared_tests_flags ${counter} test_flags)
    add_executable(${test_name} ${test_name}.c)
    if(${TARGET} STREQUAL "server")
        target_link_libraries(
            ${test_name}
            ${TEST_DEPS}
        )
    else()
        target_link_libraries(
            ${test_name}
            ${TEST_DEPS}
        )
    endif()
    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

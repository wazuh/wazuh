

# Generate msgs tests
list(APPEND os_crypto_shared_tests_names "test_msgs")
list(APPEND os_crypto_shared_tests_flags "-Wl,--wrap,merror_exit -Wl,--wrap,isChroot -Wl,--wrap,linked_queue_push_ex -Wl,--wrap,fprintf -Wl,--wrap,fopen -Wl,--wrap,fread -Wl,--wrap,fwrite -Wl,--wrap,fclose -Wl,--wrap,remove \
                            -Wl,--wrap,_mdebug2 -Wl,--wrap,sleep -Wl,--wrap,fgets -Wl,--wrap,fflush -Wl,--wrap,fseek \
                            -Wl,--wrap,stat -Wl,--wrap,getpid -Wl,--wrap=key_lock_write -Wl,--wrap=key_unlock -Wl,--wrap=time")

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

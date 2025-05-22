cmake_minimum_required(VERSION 3.10)

project(extended_sources_users_unit_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../external/googletest/lib/)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(TEST_SRC test_logged_in_users_win.cpp)
    set(TEST_SRC_FILES_USERS test_users_windows.cpp)
else()
    set(TEST_SRC test_logged_in_users_unix.cpp)

    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(TEST_SRC_FILES_USERS test_users_darwin.cpp)
    else()
        set(TEST_SRC_FILES_USERS test_users_linux.cpp)
    endif()
endif()

add_executable(extended_sources_users_unit_test ${TEST_SRC})
add_executable(users_collector_unit_test ${TEST_SRC_FILES_USERS})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(extended_sources_users_unit_test
        logged_in_users
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        psapi
        iphlpapi
        ws2_32
        wbemuuid
        advapi32
        kernel32
        user32
        gdi32
        winspool
        shell32
        uuid
        ole32
        oleaut32
        wtsapi32
        -static-libgcc -static-libstdc++
    )
    target_link_libraries(users_collector_unit_test
        users_collector
        gtestd
        gmockd
        gtest_maind
        gmock_maind
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(extended_sources_users_unit_test
        logged_in_users
        gtestd
        gmockd
        gtest_maind
        gmock_maind
        pthread
    )
    target_link_libraries(users_collector_unit_test
        users_collector
        gtestd
        gmockd
        gtest_maind
        gmock_maind
        pthread
    )
endif()

add_test(NAME LoggedInUsersTests COMMAND extended_sources_users_unit_test)
add_test(NAME UsersTests COMMAND users_collector_unit_test)

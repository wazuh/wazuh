cmake_minimum_required(VERSION 3.10)

project(extended_sources_users_unit_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../external/googletest/lib/)

if(UNIX)
    set(TEST_SRC test_logged_in_users_unix.cpp)
elseif(WIN32)
    set(TEST_SRC test_logged_in_users_win.cpp)
else()
    message(FATAL_ERROR "Unsupported platform for tests")
endif()

add_executable(extended_sources_users_unit_test ${TEST_SRC})

if(UNIX)
    target_link_libraries(extended_sources_users_unit_test
        logged_in_users
        gtestd
        gmockd
        gtest_maind
        gmock_maind
        pthread
    )
elseif(WIN32)
    message("Linking with Windows libraries")
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
endif()

add_test(NAME LoggedInUsersTests COMMAND extended_sources_users_unit_test)

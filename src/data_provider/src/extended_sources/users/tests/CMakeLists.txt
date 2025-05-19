cmake_minimum_required(VERSION 3.10)

project(extended_sources_users_unit_test)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../external/googletest/lib/)

set(TEST_SRC "main.cpp")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    list(APPEND TEST_SRC test_logged_in_users_win.cpp)
else()
    list(APPEND TEST_SRC test_logged_in_users_unix.cpp)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        list(APPEND TEST_SRC test_shadow_linux.cpp)
        list(APPEND TEST_SRC test_users_linux.cpp)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        list(APPEND TEST_SRC test_users_darwin.cpp)
    endif()
endif()

add_executable(extended_sources_users_unit_test ${TEST_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(extended_sources_users_unit_test
        users
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        wtsapi32
    )
else()
    target_link_libraries(extended_sources_users_unit_test
        users
        gtestd
        gmockd
        gtest_maind
        gmock_maind
        pthread
    )
endif()

add_test(NAME LoggedInUsersTests COMMAND extended_sources_users_unit_test)

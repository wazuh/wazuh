include_directories(${CMAKE_SOURCE_DIR}/../../../../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../../../../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../../../../external/googletest/lib/)

if(UNIX)
    set(TEST_SRC_FILES_LOGGED_USERS test_logged_in_users_unix.cpp)

    if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        set(TEST_SRC_FILES_USERS test_users_darwin.cpp)
    else()
        set(TEST_SRC_FILES_USERS test_users_linux.cpp)
    endif()
elseif(WIN32)
   set(SRC_FILES_LOGGED_USERS src/logged_in_users_windows.cpp)
   set(SRC_FILES_USERS src/users_windows.cpp)
else()
    message(FATAL_ERROR "Unsupported platform for tests")
endif()

add_executable(test_logged_in_users ${TEST_SRC_FILES_LOGGED_USERS})

target_link_libraries(test_logged_in_users
    logged_in_users_collector
    gtestd
    gmockd
    gtest_maind
    gmock_maind
    pthread
)

add_executable(test_users ${TEST_SRC_FILES_USERS})

target_link_libraries(test_users
    users_collector
    gtestd
    gmockd
    gtest_maind
    gmock_maind
    pthread
)

add_test(NAME LoggedInUsersTests COMMAND test_logged_in_users)

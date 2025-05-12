include_directories(${CMAKE_SOURCE_DIR}/../../../../external/googletest/googletest/include/)
include_directories(${CMAKE_SOURCE_DIR}/../../../../external/googletest/googlemock/include/)
link_directories(${CMAKE_SOURCE_DIR}/../../../../external/googletest/lib/)

if(UNIX)
    set(TEST_SRC test_logged_in_users_unix.cpp)
elseif(WIN32)
else()
    message(FATAL_ERROR "Unsupported platform for tests")
endif()

add_executable(test_logged_in_users ${TEST_SRC})

target_link_libraries(test_logged_in_users
    logged_in_users
    gtestd
    gmockd
    gtest_maind
    gmock_maind
    pthread
)

add_test(NAME LoggedInUsersTests COMMAND test_logged_in_users)

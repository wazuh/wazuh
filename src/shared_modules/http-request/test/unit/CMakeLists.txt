cmake_minimum_required(VERSION 3.12.4)
project(urlrequest_unit_test)

file(GLOB URL_REQUEST_UNIT_TEST_SRC *.cpp)

add_executable(urlrequest_unit_test ${URL_REQUEST_UNIT_TEST_SRC})
target_link_libraries(urlrequest_unit_test urlrequest
    gtest
    gmock
    gtest_main
    gmock_main)

add_test(NAME urlrequest_unit_test
         COMMAND urlrequest_unit_test)

cmake_minimum_required(VERSION 3.12.4)
project(urlrequest_component_test)

file(GLOB URL_REQUEST_COMPONENT_TEST_SRC *.cpp)

add_executable(urlrequest_component_test ${URL_REQUEST_COMPONENT_TEST_SRC})
target_link_libraries(urlrequest_component_test urlrequest
    gtest
    gmock
    gtest_main
    gmock_main)

add_test(NAME urlrequest_component_test
         COMMAND urlrequest_component_test)

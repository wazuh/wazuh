cmake_minimum_required(VERSION 3.12.4)
project(urlrequest_component_test)

file(GLOB URL_REQUEST_COMPONENT_TEST_SRC *.cpp)

add_executable(urlrequest_component_test ${URL_REQUEST_COMPONENT_TEST_SRC})
target_link_libraries(urlrequest_component_test urlrequest
    gtest
    #debug gtestd
    #debug gmockd
    #debug gtest_maind
    #debug gmock_maind
    #optimized gtestd
    #optimized gmockd
    #optimized gtest_maind
    #optimized gmock_maind
    )

add_test(NAME urlrequest_component_test
         COMMAND urlrequest_component_test)

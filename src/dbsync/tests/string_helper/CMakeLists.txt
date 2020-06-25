cmake_minimum_required(VERSION 3.12)

project(string_helper_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
file(GLOB STRING_HELPER_UNITTEST_SRC
    "*.cpp")

add_executable(string_helper_unit_test 
    "${STRING_HELPER_UNITTEST_SRC}" )

target_link_libraries(string_helper_unit_test 
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
)

add_test(NAME string_helper_unit_test
         COMMAND string_helper_unit_test)
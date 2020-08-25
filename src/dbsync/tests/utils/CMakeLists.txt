cmake_minimum_required(VERSION 3.12)

project(utils_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/utils/)
file(GLOB UTILS_UNITTEST_SRC
    "*.cpp")

add_executable(utils_unit_test 
    "${UTILS_UNITTEST_SRC}" )
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(utils_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtest
        optimized gmock
        optimized gtest_main
        optimized gmock_main
        pthread
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(utils_unit_test
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
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME utils_unit_test
         COMMAND utils_unit_test)
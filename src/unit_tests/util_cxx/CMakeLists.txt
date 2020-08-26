cmake_minimum_required(VERSION 3.12)

project(utils_cxx_unit_test)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${SRC_FOLDER}/util/cxx/)
include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

file(GLOB UTIL_CXX_UNITTEST_SRC
    "*.cpp")

link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(utils_cxx_unit_test 
    "${UTIL_CXX_UNITTEST_SRC}")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(utils_cxx_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtestd
        optimized gmockd
        optimized gtest_maind
        optimized gmock_maind
        pthread
        gcov
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(utils_cxx_unit_test
        debug gtestd
        debug gmockd
        debug gtest_maind
        debug gmock_maind
        optimized gtestd
        optimized gmockd
        optimized gtest_maind
        optimized gmock_maind
        gcov
        pthread
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_test(NAME utils_cxx_unit_test
         COMMAND utils_cxx_unit_test)
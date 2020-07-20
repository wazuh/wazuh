cmake_minimum_required(VERSION 3.12)

project(dbengine_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g -std=c++11 -fsanitize=address,leak,undefined --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)


file(GLOB STRING_HELPER_UNITTEST_SRC
    "*.cpp")

add_executable(dbengine_unit_test 
    "${STRING_HELPER_UNITTEST_SRC}" )

target_link_libraries(dbengine_unit_test 
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
    dbsync 
    dl
)

add_test(NAME dbengine_unit_test
         COMMAND dbengine_unit_test)
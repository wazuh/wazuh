cmake_minimum_required(VERSION 3.12)

project(fim_integration_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)


file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp")

add_executable(fim_integration_test 
    "${INTERFACE_UNITTEST_SRC}" )

target_link_libraries(fim_integration_test 
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
add_test(NAME fim_integration_test
         COMMAND fim_integration_test)
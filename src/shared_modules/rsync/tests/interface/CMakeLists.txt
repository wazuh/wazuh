cmake_minimum_required(VERSION 3.12)

project(rsync_unit_test)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage")

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)


file(GLOB INTERFACE_UNITTEST_SRC
    "*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_executable(rsync_unit_test 
    "${INTERFACE_UNITTEST_SRC}" )

target_link_libraries(rsync_unit_test 
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    pthread
    rsync 
    dl
)

add_test(NAME rsync_unit_test
         COMMAND rsync_unit_test)
cmake_minimum_required(VERSION 3.10)
project(bounded_queue_test)

set(CMAKE_CXX_STANDARD 14)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(bounded_queue_test bounded_queue_test.cpp)

target_link_libraries(bounded_queue_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
)

add_test(NAME bounded_queue_test
         COMMAND bounded_queue_test)
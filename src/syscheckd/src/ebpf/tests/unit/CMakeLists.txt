cmake_minimum_required(VERSION 3.10)
project(bounded_queue_test)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")

if (NOT SRC_FOLDER)
    get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(bounded_queue_test bounded_queue_test.cpp)

target_link_libraries(bounded_queue_test
    gtest_main
    gmock_main
    gtest
    gmock
    pthread
    -fsanitize=address
    -fsanitize=undefined
)

add_test(NAME bounded_queue_test
         COMMAND bounded_queue_test)

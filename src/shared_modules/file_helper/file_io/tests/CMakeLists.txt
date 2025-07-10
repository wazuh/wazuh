include_directories(${SRC_FOLDER}/../external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/../external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/../external/googletest/lib/)

add_executable(file_io_unit_test file_io_utils_test.cpp)
target_include_directories(file_io_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(file_io_unit_test PRIVATE FileIO
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)
add_test(NAME FileIO COMMAND file_io_unit_test)

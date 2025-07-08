find_package(GTest CONFIG REQUIRED)

add_executable(file_io_test file_io_utils_test.cpp)
target_include_directories(file_io_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(file_io_test PRIVATE FileIO GTest::gtest GTest::gmock)
add_test(NAME FileIO COMMAND file_io_test)

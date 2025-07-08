find_package(GTest CONFIG REQUIRED)

add_executable(filesystem_test filesystem_utils_test.cpp)
target_include_directories(filesystem_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(filesystem_test PRIVATE FilesystemWrapper GTest::gtest GTest::gmock)
add_test(NAME Filesystem COMMAND filesystem_test)

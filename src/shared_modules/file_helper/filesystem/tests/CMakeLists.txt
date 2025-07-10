include_directories(${SRC_FOLDER}/../external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/../external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/../external/googletest/lib/)

add_executable(filesystem_unit_test filesystem_utils_test.cpp)
target_include_directories(filesystem_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_link_libraries(filesystem_unit_test PRIVATE FilesystemWrapper
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
)
add_test(NAME Filesystem COMMAND filesystem_unit_test)

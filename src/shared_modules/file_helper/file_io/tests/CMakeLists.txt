include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(file_io_unit_test file_io_utils_test.cpp)
target_include_directories(file_io_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_include_directories(file_io_unit_test PRIVATE ${SRC_FOLDER}/external/googletest/googletest/include)
target_include_directories(file_io_unit_test PRIVATE ${SRC_FOLDER}/external/googletest/googlemock/include)
target_link_libraries(file_io_unit_test PRIVATE FileIO
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    $<$<PLATFORM_ID:Windows>:-static-libgcc>
    $<$<PLATFORM_ID:Windows>:-static-libstdc++>
)
add_test(NAME FileIO COMMAND file_io_unit_test)
set_tests_properties(FileIO PROPERTIES LABELS file_helper_utest)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(filesystem_unit_test filesystem_utils_test.cpp)
target_include_directories(filesystem_unit_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src)
target_include_directories(filesystem_unit_test PRIVATE ${SRC_FOLDER}/external/googletest/googletest/include)
target_include_directories(filesystem_unit_test PRIVATE ${SRC_FOLDER}/external/googletest/googlemock/include)
target_link_libraries(filesystem_unit_test PRIVATE FilesystemWrapper
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
add_test(NAME Filesystem COMMAND filesystem_unit_test)
set_tests_properties(Filesystem PROPERTIES LABELS file_helper_utest)

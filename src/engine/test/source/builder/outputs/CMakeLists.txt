# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
# Configuration router test
add_executable(file_output_test
  ${ENGINE_SOURCE_DIR}/builder/outputs/file_output.hpp
  ${TEST_SOURCE_DIR}/builder/outputs/file_output_test.cpp
)

target_include_directories(file_output_test PUBLIC
    ${ENGINE_SOURCE_DIR}/
    ${RapidJSON_SOURCE_DIR}/include/
)

target_link_libraries(file_output_test gtest_main rxcpp)
gtest_discover_tests(file_output_test)

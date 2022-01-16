# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
# Configuration router test
add_executable(fileOutput_test 
  ${ENGINE_SOURCE_DIR}/builder/outputs/file/fileOutput.hpp
  ${TEST_SOURCE_DIR}/builder/outputs/file/fileOutput_test.cpp
)

target_include_directories(fileOutput_test PUBLIC 
    ${ENGINE_SOURCE_DIR}/
    ${RapidJSON_SOURCE_DIR}/include/
)

target_link_libraries(fileOutput_test gtest_main rxcpp)
gtest_discover_tests(fileOutput_test)

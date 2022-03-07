# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
# Configuration router test
add_executable(fileOutputTest
  ${ENGINE_SOURCE_DIR}/builder/outputs/file.hpp
  ${TEST_SOURCE_DIR}/builder/outputs/fileOutputTest.cpp
)

target_include_directories(fileOutputTest PUBLIC
    ${ENGINE_SOURCE_DIR}/json
    ${ENGINE_SOURCE_DIR}/builder
    ${RapidJSON_SOURCE_DIR}/include
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

target_link_libraries(fileOutputTest gtest_main)
gtest_discover_tests(fileOutputTest)

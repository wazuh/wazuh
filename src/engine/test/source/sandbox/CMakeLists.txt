# dependencies
# Processor test
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  OPTIONS
    "MAKE_BUILD_TYPE RelWithDebInfo"
)


# Configuration sandbox test
add_executable(sandbox_test 
  ${ENGINE_SOURCE_DIR}/sandbox/sandbox.cpp
  ${ENGINE_SOURCE_DIR}/sandbox/environment.cpp
  ${TEST_SOURCE_DIR}/sandbox/sandbox_test.cpp
  ${TEST_SOURCE_DIR}/sandbox/environment_test.cpp
  ${TEST_SOURCE_DIR}/sandbox/router_test.cpp
)

target_include_directories(sandbox_test PUBLIC "${ENGINE_SOURCE_DIR}/")
target_link_libraries(sandbox_test gtest_main rxcpp "nlohmann_json::nlohmann_json")
gtest_discover_tests(sandbox_test)

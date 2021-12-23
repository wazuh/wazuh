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


# Configuration router test
add_executable(router_test 
  ${ENGINE_SOURCE_DIR}/router/router.cpp
  ${ENGINE_SOURCE_DIR}/router/router.hpp
  ${TEST_SOURCE_DIR}/router/router_test.cpp
  ${TEST_SOURCE_DIR}/router/router_test.hpp
)

target_include_directories(router_test PUBLIC "${ENGINE_SOURCE_DIR}/")
target_link_libraries(router_test gtest_main rxcpp "nlohmann_json::nlohmann_json")
gtest_discover_tests(router_test)

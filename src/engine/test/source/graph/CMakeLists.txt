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


# Configuration graph test
add_executable(graph_test 
  ${ENGINE_SOURCE_DIR}/graph/graph.hpp
  ${TEST_SOURCE_DIR}/graph/graph_test.cpp
  ${TEST_SOURCE_DIR}/graph/graph_test.hpp
)

target_include_directories(graph_test PUBLIC "${ENGINE_SOURCE_DIR}/")
target_link_libraries(graph_test gtest_main rxcpp)
gtest_discover_tests(graph_test)

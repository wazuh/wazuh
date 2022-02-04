# dependencies
# Processor test
CPMAddPackage(
  NAME PEGTL
  GITHUB_REPOSITORY taocpp/PEGTL
  GIT_TAG 3.2.2
  VERSION 3.2.2
  OPTIONS
    "MAKE_BUILD_TYPE RelWithDebInfo"
)

# Configuration router test
add_executable(parser_test 
  ${TEST_SOURCE_DIR}/parser/parser_test.cpp
  ${TEST_SOURCE_DIR}/parser/parser_test.hpp
)
target_include_directories(parser_test PRIVATE "${ENGINE_SOURCE_DIR}/" "${PEGTL_SOURCE_DIR}/include/")
target_link_libraries(parser_test gtest_main)
gtest_discover_tests(parser_test)

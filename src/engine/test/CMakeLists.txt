cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

project(wazuh-engine)

set(TEST_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/source)

# Add googletest as CPM dependency
include(../cmake/CPM.cmake)
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  GIT_TAG release-1.11.0
  VERSION 1.11.0
  OPTIONS
      "INSTALL_GTEST OFF"
)



# Add unit tests here
file(GLOB SOURCE_FILES ${TEST_SOURCE_DIR}/*.cpp)

# Build unit tests
add_executable(unit_tests ${SOURCE_FILES})
# target_link_libraries(unit_tests gtest_main bechmark_main)
target_link_libraries(unit_tests gtest_main)
include(GoogleTest)
gtest_discover_tests(unit_tests)


add_subdirectory(${TEST_SOURCE_DIR}/catalog)
add_subdirectory(${TEST_SOURCE_DIR}/cliParser)

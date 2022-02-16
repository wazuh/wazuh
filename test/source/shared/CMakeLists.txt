cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

####################################################################################################
# Settings
####################################################################################################
project(wazuh-engine)

set(SHARED_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/shared)
set(SHARED_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/shared)

####################################################################################################
# Dependencies -- assuming cpm is available
####################################################################################################
# google/googletest
CPMAddPackage(
  NAME googletest
  GITHUB_REPOSITORY google/googletest
  GIT_TAG release-1.11.0
  VERSION 1.11.0
  OPTIONS
      "INSTALL_GTEST OFF"
)

####################################################################################################
# Headers -- Libraries
####################################################################################################
include_directories(
  ${ENGINE_SOURCE_DIR}
  ${SHARED_ENGINE_SOURCE_DIR}
  ${SHARED_TEST_SOURCE_DIR}
)

link_libraries(
  glog::glog
  gtest_main
)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(stringUtils_test
  ${SHARED_TEST_SOURCE_DIR}/stringUtils_test.cpp
  ${SHARED_ENGINE_SOURCE_DIR}/stringUtils.cpp
)
target_link_libraries(stringUtils_test glog::glog)
gtest_discover_tests(stringUtils_test)

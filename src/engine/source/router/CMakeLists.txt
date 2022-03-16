# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

set(ROUTER_SERVER_SOURCE_DIR ${ENGINE_SOURCE_DIR}/router)

####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  OPTIONS
    "RXCPP_DISABLE_TESTS_AND_EXAMPLES"
)

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
target_include_directories(main PUBLIC
    ${ROUTER_SERVER_SOURCE_DIR}
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

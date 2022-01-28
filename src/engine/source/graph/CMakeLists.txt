# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project Settings
project(wazuh-engine)

set(GRAPH_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/graph)

####################################################################################################
# Dependencies
####################################################################################################
# ReactiveX/RxCpp
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
)
list(APPEND EXTERNAL_DEPS "rxcpp")

# Add this dependencies to parent CMakeLists scope
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

####################################################################################################
# Sources - Includes
####################################################################################################
target_include_directories(main PUBLIC
    ${GRAPH_ENGINE_SOURCE_DIR}
)

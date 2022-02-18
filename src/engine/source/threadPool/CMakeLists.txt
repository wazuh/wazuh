# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

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
target_sources(main PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/threadPool.cpp
)

target_include_directories(main PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}
)

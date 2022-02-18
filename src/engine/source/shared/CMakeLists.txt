# Minimum 3.14 required by googletest discover tests
cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

# Set c++17
set(CMAKE_CXX_STANDARD 17)

# Project settings
project(wazuh-engine)

set(SHARED_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/shared)

####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main PRIVATE
    ${SHARED_ENGINE_SOURCE_DIR}/stringUtils.cpp
)

target_include_directories(main PUBLIC
    ${SHARED_ENGINE_SOURCE_DIR}
)

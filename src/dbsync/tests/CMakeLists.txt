cmake_minimum_required(VERSION 3.12)

project(unit_tests)

include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${CMAKE_SOURCE_DIR}/src/sqlite/)

add_subdirectory(utils)
add_subdirectory(sqlite)
add_subdirectory(interface)
add_subdirectory(pipelineFactory)
add_subdirectory(dbengine)

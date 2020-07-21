cmake_minimum_required(VERSION 3.12)

project(unit_tests)

include_directories(${EXTERNAL_LIB}/googletest/googletest/include/)
include_directories(${EXTERNAL_LIB}/googletest/googlemock/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${CMAKE_SOURCE_DIR}/src/sqlite/)
link_directories(${EXTERNAL_LIB}/googletest/lib/)



add_subdirectory(utils)
add_subdirectory(sqlite)
add_subdirectory(interface)
add_subdirectory(pipelineFactory)
add_subdirectory(dbengine)

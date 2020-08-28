cmake_minimum_required(VERSION 3.12)

project(unit_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)


add_subdirectory(interface)
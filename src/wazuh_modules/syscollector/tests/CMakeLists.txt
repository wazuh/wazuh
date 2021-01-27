cmake_minimum_required(VERSION 3.12.4)

project(unit_tests)

include_directories(${CMAKE_SOURCE_DIR})

add_subdirectory(sysCollectorImp)
add_subdirectory(sysNormalizer)


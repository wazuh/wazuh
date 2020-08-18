cmake_minimum_required(VERSION 3.12)

project(rsync)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/)

file(GLOB RSYNC_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_library(rsync SHARED
    "${RSYNC_SRC}" )
    
if(UNIT_TEST)
  target_link_libraries(rsync gcov)
else()
  target_link_libraries(rsync)
endif(UNIT_TEST)

if(UNIT_TEST)
  add_subdirectory(tests)
  add_subdirectory(integrationTests)
endif(UNIT_TEST)

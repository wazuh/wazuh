cmake_minimum_required(VERSION 3.12)

project(dbsync_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

add_executable(dbsync_test_tool
               "${CMAKE_SOURCE_DIR}/testtool/main.cpp" )

target_link_libraries(dbsync_test_tool 
    dbsync 
    pthread 
    dl 
)
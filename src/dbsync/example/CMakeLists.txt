cmake_minimum_required(VERSION 3.12)

project(dbsync_example)

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)

add_executable(dbsync_example 
    "${CMAKE_SOURCE_DIR}/example/main.cpp" )

target_link_libraries(dbsync_example 
    dbsync 
    pthread 
    dl 
)
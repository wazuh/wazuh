cmake_minimum_required(VERSION 2.6.4)

project(dbsync_example)

include_directories(${CMAKE_SOURCE_DIR}/include/)
link_directories(${CMAKE_BINARY_DIR}/lib)

if(COVERITY)
  set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14")
else()
  set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++11")
endif(COVERITY)

add_executable(dbsync_example 
    "${CMAKE_SOURCE_DIR}/example/main.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(dbsync_example
	    dbsync
	    pthread
	    -static-libgcc -static-libstdc++
	)
else()
	target_link_libraries(dbsync_example
	    dbsync
	    pthread
	    dl
	)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
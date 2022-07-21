cmake_minimum_required(VERSION 3.12.4)

project(dbsync_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/utils/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -std=c++14 -pthread")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address,leak,undefined")
endif(FSANITIZE)

add_executable(dbsync_test_tool
               ${CMAKE_SOURCE_DIR}/testtool/main.cpp )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(dbsync_test_tool
	    dbsync
	    -static-libstdc++
	)
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	target_link_libraries(dbsync_test_tool
	    dbsync
	    pthread)
else()
	target_link_libraries(dbsync_test_tool
	    dbsync
	    pthread
	    dl
	)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

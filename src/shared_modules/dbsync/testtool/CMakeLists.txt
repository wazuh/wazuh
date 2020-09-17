cmake_minimum_required(VERSION 3.12)

project(dbsync_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/utils/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

if(COVERITY)
  set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14")
else()
  set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++11")
endif(COVERITY)

add_executable(dbsync_test_tool
               "${CMAKE_SOURCE_DIR}/testtool/main.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(dbsync_test_tool
	    dbsync
	    -static-libgcc -static-libstdc++
	)
else()
	target_link_libraries(dbsync_test_tool
	    dbsync
	    pthread
	    dl
	)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
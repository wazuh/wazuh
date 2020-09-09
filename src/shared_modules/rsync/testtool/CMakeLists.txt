cmake_minimum_required(VERSION 3.12)

project(rsync_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/utils/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

set(CMAKE_CXX_FLAGS_DEBUG "-g -std=c++11")

add_executable(rsync_test_tool
               "${CMAKE_SOURCE_DIR}/testtool/main.cpp"
               "${CMAKE_SOURCE_DIR}/testtool/agentEmulator.cpp"
               "${CMAKE_SOURCE_DIR}/testtool/managerEmulator.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(rsync_test_tool
	    rsync
	    dbsync
	    -static-libgcc -static-libstdc++
	)
else()
	target_link_libraries(rsync_test_tool
	    rsync
	    dbsync
	    pthread
	    dl
	)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
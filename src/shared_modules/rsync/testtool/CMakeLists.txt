cmake_minimum_required(VERSION 2.6.4)

project(rsync_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/utils/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
link_directories(${CMAKE_BINARY_DIR}/lib)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14")

add_executable(rsync_test_tool
               "${CMAKE_SOURCE_DIR}/testtool/main.cpp"
               "${CMAKE_SOURCE_DIR}/testtool/agentEmulator.cpp"
               "${CMAKE_SOURCE_DIR}/testtool/oneTimeSync.cpp"
               "${CMAKE_SOURCE_DIR}/testtool/managerEmulator.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(rsync_test_tool
	    rsync
	    dbsync
	    -static-libgcc -static-libstdc++
	)
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	target_link_libraries(rsync_test_tool
	    rsync
	    dbsync)
else()
	target_link_libraries(rsync_test_tool
	    rsync
	    dbsync
	    dl
	)

	if(SOLARIS)
		target_link_libraries(rsync_test_tool
			nsl
			socket
		)
	endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

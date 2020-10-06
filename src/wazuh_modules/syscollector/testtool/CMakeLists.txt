cmake_minimum_required(VERSION 2.6.4)

project(syscollector_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/)
include_directories(${CMAKE_SOURCE_DIR}/testtool/)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/rsync/include/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/rsync/build/lib)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++14")

add_executable(syscollector_test_tool
               "${CMAKE_SOURCE_DIR}/testtool/main.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(syscollector_test_tool
	    rsync
	    dbsync
	    -static-libgcc -static-libstdc++
	)
else()
	target_link_libraries(syscollector_test_tool
	    rsync
	    dbsync
	    dl
	)

	if(SOLARIS)
		target_link_libraries(syscollector_test_tool
			nsl
			socket
		)
	endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
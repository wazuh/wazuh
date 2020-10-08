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
add_definitions(-DENABLE_SYSC=1)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	file(GLOB SYSCOLLECTOR_TESTTOOL_SRC
	    "${CMAKE_SOURCE_DIR}/*Win.cpp")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
	file(GLOB SYSCOLLECTOR_TESTTOOL_SRC
	    "${CMAKE_SOURCE_DIR}/*Linux.cpp")
else(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
	file(GLOB SYSCOLLECTOR_TESTTOOL_SRC
	    "${CMAKE_SOURCE_DIR}/*Mac.cpp")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

add_executable(syscollector_test_tool
               "${SYSCOLLECTOR_TESTTOOL_SRC}"
               "${CMAKE_SOURCE_DIR}/testtool/main.cpp"
               "${CMAKE_SOURCE_DIR}/syscollectorImp.cpp")

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
	    pthread
	)

	if(SOLARIS)
		target_link_libraries(syscollector_test_tool
			nsl
			socket
		)
	endif(SOLARIS)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
project(dbsync_test_tool)

add_executable(dbsync_test_tool
	${PROJECT_SOURCE_DIR}/main.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(dbsync_test_tool
		dbsync
		-static-libstdc++
	)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
	target_link_libraries(dbsync_test_tool
		dbsync
		pthread)
else()
	target_link_libraries(dbsync_test_tool
		dbsync
		pthread
		dl
	)
endif()

project(rsync_test_tool)

add_executable(rsync_test_tool
    "${PROJECT_SOURCE_DIR}/main.cpp"
    "${PROJECT_SOURCE_DIR}/agentEmulator.cpp"
    "${PROJECT_SOURCE_DIR}/oneTimeSync.cpp"
    "${PROJECT_SOURCE_DIR}/managerEmulator.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
	target_link_libraries(rsync_test_tool
	    rsync
	    dbsync
	    -static-libstdc++
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
endif()

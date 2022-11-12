add_subdirectory(dbsync)
add_subdirectory(rsync)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_subdirectory(utils/tests)
endif()

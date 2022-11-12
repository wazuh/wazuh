project(dbsync_example)

add_executable(dbsync_example
    "${PROJECT_SOURCE_DIR}/main.cpp" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbsync_example
        dbsync
        pthread
        -static-libgcc -static-libstdc++
    )
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    target_link_libraries(dbsync_example
        dbsync
        pthread)
else()
    target_link_libraries(dbsync_example
        dbsync
        pthread
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

cmake_minimum_required(VERSION 3.12.4)

project(fimdb_test_tool)

include_directories(${CMAKE_SOURCE_DIR}/testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

if(COVERITY)
    add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -std=c++14 -pthread")

if(FSANITIZE)
    set(CMAKE_CXX_FLAGS_DEBUG "-fsanitize=address,leak,undefined")
endif(FSANITIZE)

add_executable(fimdb_test_tool
               ${CMAKE_SOURCE_DIR}/src/db/testtool/main.cpp )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_definitions(-DOS_TYPE=OSType::WINDOWS)
    target_link_libraries(fimdb_test_tool
        rsync
        fimdb
        dbsync
        -static-libstdc++
    )
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    add_definitions(-DOS_TYPE=OSType::OTHERS)
    target_link_libraries(fimdb_test_tool
        dbsync
        fimdb
        rsync
        pthread
    )
else()
    add_definitions(-DOS_TYPE=OSType::OTHERS)
    target_link_libraries(fimdb_test_tool
        dbsync
        fimdb
        rsync
        pthread
        dl
    )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

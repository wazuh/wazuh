cmake_minimum_required(VERSION 3.12)

project(dbsync)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_BUILD_TYPE RelWithDebInfo)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${EXTERNAL_LIB}/sqlite/)
include_directories(${EXTERNAL_LIB}/nlohmann/)
include_directories(${EXTERNAL_LIB}/cJSON/)
link_directories(${EXTERNAL_LIB}/sqlite/)
link_directories(${EXTERNAL_LIB}/cJSON/)

file(GLOB DBSYNC_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp")

add_library(dbsync SHARED 
    "${DBSYNC_SRC}" )

target_link_libraries(dbsync sqlite3 cjson)

add_subdirectory(example)
cmake_minimum_required(VERSION 3.12)

project(dbsync)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-Wall -Wextra -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/utils/)
include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${EXTERNAL_LIB}/sqlite/)
include_directories(${EXTERNAL_LIB}/nlohmann/)
include_directories(${EXTERNAL_LIB}/cJSON/)
link_directories(${EXTERNAL_LIB}/sqlite/)
link_directories(${EXTERNAL_LIB}/cJSON/)

file(GLOB DBSYNC_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/sqlite/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/utils/*.cpp")

add_library(dbsync SHARED 
    "${DBSYNC_SRC}" )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN_EXPORT)
  set_target_properties(dbsync PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
        LINK_FLAGS "-Wl,--add-stdcall-alias -static-libgcc -static-libstdc++"
        POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
        # MinGW generates position-independent-code for DLL by default
  )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    
if(UNIT_TEST)
  target_link_libraries(dbsync sqlite3 cjson gcov)
else()
  target_link_libraries(dbsync sqlite3 cjson)
endif(UNIT_TEST)

add_subdirectory(example)
add_subdirectory(testtool)

if(UNIT_TEST)
  add_subdirectory(tests)
  add_subdirectory(integrationTests)
endif(UNIT_TEST)

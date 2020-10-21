cmake_minimum_required(VERSION 2.6.4)

project(dbsync)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
get_filename_component(SRC_FOLDER     ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)

if(COVERITY)
  add_definitions(-D__GNUC__=8)
endif(COVERITY)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -std=c++14")

set(CMAKE_CXX_FLAGS_DEBUG "-g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${CMAKE_SOURCE_DIR}/include/)
include_directories(${CMAKE_SOURCE_DIR}/src/)
include_directories(${SHARED_MODULES}/utils/)
include_directories(${SHARED_MODULES}/common/)

link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)

link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)

file(GLOB DBSYNC_SRC
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/sqlite/*.cpp")

add_library(dbsync SHARED 
    ${DBSYNC_SRC} )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN_EXPORT)
  set_target_properties(dbsync PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
        LINK_FLAGS "-Wl,--add-stdcall-alias -static-libgcc -static-libstdc++"
        POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
        # MinGW generates position-independent-code for DLL by default
  )
else()
  set_target_properties(dbsync PROPERTIES
        LINK_FLAGS "-static-libgcc -static-libstdc++"
  )
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  target_link_libraries(dbsync sqlite3 cjson gcov)
  if(UNIT_TEST)
    include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
    include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

    link_directories(${SRC_FOLDER}/external/googletest/lib/)

    add_subdirectory(tests)
    add_subdirectory(integrationTests)
  endif(UNIT_TEST)
else()
    target_link_libraries(dbsync sqlite3 cjson)
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

if(NOT DEFINED COVERITY)
add_subdirectory(example)
add_subdirectory(testtool)
endif(NOT DEFINED COVERITY)

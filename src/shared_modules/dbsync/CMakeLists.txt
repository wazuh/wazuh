project(dbsync)

include_directories(${PROJECT_SOURCE_DIR}/include/)
include_directories(${PROJECT_SOURCE_DIR}/src/)
include_directories(${PROJECT_SOURCE_DIR}/src/sqlite)

link_directories(${SRC_FOLDER})

file(GLOB DBSYNC_SRC
    "${PROJECT_SOURCE_DIR}/src/*.cpp"
    "${PROJECT_SOURCE_DIR}/src/sqlite/*.cpp")

add_library(dbsync SHARED
    ${DBSYNC_SRC} )

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN_EXPORT)
  set_target_properties(dbsync PROPERTIES
        PREFIX ""
        SUFFIX ".dll"
        LINK_FLAGS "-Wl,--add-stdcall-alias"
        POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
        # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
  endif()
endif()

target_link_libraries(dbsync wazuhext)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
    target_link_libraries(dbsync -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
  endif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif(CMAKE_BUILD_TYPE STREQUAL "Release")


if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_link_libraries(dbsync -fprofile-arcs)
  else()
    target_link_libraries(dbsync gcov)
  endif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")

  add_subdirectory(tests)
  add_subdirectory(integrationTests)
endif()

if(NOT DEFINED COVERITY)
  if(FSANITIZE)
      target_link_libraries(dbsync gcov)
  endif(FSANITIZE)
  add_subdirectory(example)
  add_subdirectory(testtool)
endif()

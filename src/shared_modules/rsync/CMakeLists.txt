project(rsync)

include_directories(${SHARED_MODULES}/dbsync/include/)
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/src)

file(GLOB RSYNC_SRC
  "${PROJECT_SOURCE_DIR}/src/*.cpp")

add_library(rsync SHARED
  ${RSYNC_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN_EXPORT)
  set_target_properties(rsync PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    LINK_FLAGS "-Wl,--add-stdcall-alias"
    POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;

    # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN") # target_link_options() is not available until CMake 3.13
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(rsync dbsync wazuhext)

if($<CONFIG:RELEASE>)
  if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
    target_link_libraries(rsync dbsync -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
  endif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif()

add_subdirectory(testtool)

add_subdirectory(tests EXCLUDE_FROM_ALL)
add_subdirectory(integrationTests EXCLUDE_FROM_ALL)

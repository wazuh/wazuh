project(dbsync)

include_directories(${PROJECT_SOURCE_DIR}/include/)
include_directories(${PROJECT_SOURCE_DIR}/src/)
include_directories(${PROJECT_SOURCE_DIR}/src/sqlite)

link_directories(${SRC_FOLDER})

file(GLOB DBSYNC_SRC
  "${PROJECT_SOURCE_DIR}/src/*.cpp"
  "${PROJECT_SOURCE_DIR}/src/sqlite/*.cpp")

add_library(dbsync SHARED
  ${DBSYNC_SRC})

# The debug symbols are stripped from the binary in Release mode if the compiler is not Clang
if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:-s>")
endif(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")

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
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN") # target_link_options() is not available until CMake 3.13
  endif(NOT CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(dbsync wazuhext)

if($<CONFIG:RELEASE>)
  if(CMAKE_SYSTEM_NAME STREQUAL "AIX")
    string(REPLACE ";" ":" CXX_IMPLICIT_LINK_DIRECTORIES_STR "${CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES}")
    string(REPLACE ";" ":" PLATFORM_REQUIRED_RUNTIME_PATH_STR "${CMAKE_PLATFORM_REQUIRED_RUNTIME_PATH}")
    target_link_libraries(dbsync -Wl,-blibpath:${INSTALL_PREFIX}/lib:${CXX_IMPLICIT_LINK_DIRECTORIES_STR}:${PLATFORM_REQUIRED_RUNTIME_PATH_STR})
  endif(CMAKE_SYSTEM_NAME STREQUAL "AIX")
endif()

add_subdirectory(example)
add_subdirectory(testtool)

add_subdirectory(tests EXCLUDE_FROM_ALL)
add_subdirectory(integrationTests EXCLUDE_FROM_ALL)

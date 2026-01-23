cmake_minimum_required(VERSION 3.12.4)

project(dbsync)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SHARED_MODULES ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
else()
  get_filename_component(SHARED_MODULES ${SRC_FOLDER}/shared_modules ABSOLUTE)
endif()

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif(APPLE)

include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/openssl/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/)
include_directories(${SHARED_MODULES}/utils/)
include_directories(${SHARED_MODULES}/common/)

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/sqlite/)
link_directories(${SRC_FOLDER}/external/cJSON/)

file(GLOB DBSYNC_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/src/sqlite/*.cpp")

add_library(dbsync SHARED ${DBSYNC_SRC} ${SRC_FOLDER}/${RESOURCE_OBJ})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DWIN_EXPORT)
  set_target_properties(
    dbsync
    PROPERTIES PREFIX ""
               SUFFIX ".dll"
               LINK_FLAGS "-Wl,--add-stdcall-alias"
               POSITION_INDEPENDENT_CODE 0 # this is to avoid MinGW warning;
               # MinGW generates position-independent-code for DLL by default
  )
elseif(UNIX AND NOT APPLE)
  string(APPEND CMAKE_SHARED_LINKER_FLAGS " -Wl,-rpath=$ORIGIN")
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

target_link_libraries(dbsync PUBLIC wazuhext)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(dbsync)
  add_subdirectory(tests)
  add_subdirectory(integrationTests)
endif(UNIT_TEST)

if(NOT DEFINED COVERITY AND NOT DEFINED UNIT_TEST)
  add_subdirectory(example)
endif(NOT DEFINED COVERITY AND NOT DEFINED UNIT_TEST)

add_subdirectory(testtool)

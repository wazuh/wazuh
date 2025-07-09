cmake_minimum_required(VERSION 3.22)

project(FileHandler)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# FilesystemWrapper target
if(WIN32)
    set(SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/filesystem/src/filesystem_wrapper_win.cpp)
else()
    set(SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/filesystem/src/filesystem_wrapper_unix.cpp)
endif()

list(APPEND SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/filesystem/src/filesystem_wrapper.cpp
     ${CMAKE_CURRENT_SOURCE_DIR}/filesystem/src/filesystem_utils.cpp)

get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../ ABSOLUTE)
add_library(FilesystemWrapper STATIC ${SOURCES})
set_property(TARGET FilesystemWrapper PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(FilesystemWrapper PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/filesystem/include PRIVATE ${SRC_FOLDER}/utils)

# File io target
add_library(FileIO STATIC ${CMAKE_CURRENT_SOURCE_DIR}/file_io/src/file_io_utils.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/file_io/src/file_io_wrapper.cpp)
set_property(TARGET FileIO PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(FileIO PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/file_io/include)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(filesystem/tests)
    add_subdirectory(file_io/tests)
endif()

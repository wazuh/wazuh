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

add_library(FilesystemWrapper STATIC ${SOURCES})
target_include_directories(FilesystemWrapper PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/filesystem/include)
target_link_libraries(FilesystemWrapper PRIVATE glob_helper)

# File io target
add_library(FileIO STATIC ${CMAKE_CURRENT_SOURCE_DIR}/file_io/src/file_io_utils.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/file_io/src/file_io_wrapper.cpp)
target_include_directories(FileIO PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/file_io/include)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(filesystem/tests)
    add_subdirectory(file_io/tests)
endif()

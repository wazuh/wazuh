cmake_minimum_required(VERSION 3.12.4)

project(dbsync_test_tool)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../utils/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -pthread")

add_executable(dbsync_test_tool ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

set_target_properties(
  dbsync_test_tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                              "${CMAKE_BINARY_DIR}/bin")

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(dbsync_test_tool dbsync -static-libstdc++)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  target_link_libraries(dbsync_test_tool dbsync pthread)
else()
  target_link_libraries(dbsync_test_tool dbsync pthread dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

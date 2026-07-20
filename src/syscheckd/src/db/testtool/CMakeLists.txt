cmake_minimum_required(VERSION 3.12.4)

project(fimdb_test_tool)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../testtool/)
link_directories(${CMAKE_BINARY_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "-g -Wall -Wextra -pthread")

add_executable(fimdb_test_tool ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_definitions(-DOS_TYPE=OSType::WINDOWS)
  target_link_libraries(fimdb_test_tool fimdb dbsync -static-libstdc++)
elseif(CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  add_definitions(-DOS_TYPE=OSType::OTHERS)
  target_link_libraries(fimdb_test_tool dbsync fimdb pthread)
else()
  add_definitions(-DOS_TYPE=OSType::OTHERS)
  target_link_libraries(fimdb_test_tool dbsync fimdb pthread dl)
endif(CMAKE_SYSTEM_NAME STREQUAL "Windows")

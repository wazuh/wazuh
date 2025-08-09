cmake_minimum_required(VERSION 3.12.4)

project(sync_protocol_test_tool)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/sqlite/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../external/flatbuffers/include/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../shared_modules/utils/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../)
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread")
set(CMAKE_CXX_FLAGS_DEBUG "-g")

if(FSANITIZE)
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,leak,undefined")
endif()

add_executable(sync_protocol_test_tool
  ${CMAKE_SOURCE_DIR}/testtool/main.cpp
)

target_link_libraries(sync_protocol_test_tool
  PRIVATE
  agent_sync_protocol
  pthread
)
cmake_minimum_required(VERSION 3.12.4)

project(sync_protocol_test_tool)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/sqlite/)
include_directories(${SRC_FOLDER}/external/flatbuffers/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/headers/)
include_directories(${SRC_FOLDER})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)
include_directories(${CMAKE_BINARY_DIR}/shared_modules/sync_protocol)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

add_executable(sync_protocol_test_tool ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

set_target_properties(
  sync_protocol_test_tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                     "${CMAKE_BINARY_DIR}/bin")

target_link_libraries(sync_protocol_test_tool PRIVATE agent_sync_protocol
                                                      pthread)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT CMAKE_SYSTEM_NAME STREQUAL
                                                "Darwin")
  target_link_libraries(sync_protocol_test_tool PRIVATE dl)
endif()

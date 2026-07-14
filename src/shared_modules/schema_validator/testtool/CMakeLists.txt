cmake_minimum_required(VERSION 3.12.4)

project(schema_validator_test_tool)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER})
include_directories(${SRC_FOLDER}/external/nlohmann)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../include)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../src)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

add_executable(schema_validator_test_tool ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp)

set_target_properties(
  schema_validator_test_tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                        "${CMAKE_BINARY_DIR}/bin")

target_link_libraries(schema_validator_test_tool PRIVATE schema_validator pthread)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows" AND NOT CMAKE_SYSTEM_NAME STREQUAL
                                                "Darwin")
  target_link_libraries(schema_validator_test_tool PRIVATE dl)
endif()

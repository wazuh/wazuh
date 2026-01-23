cmake_minimum_required(VERSION 3.12.4)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/headers/)

# Copy input files to the build directory
file(COPY input DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB INDEXER_CONNECTOR_TOOL_SRC "*.cpp")

# Add address sanitizer

add_executable(indexer_connector_tool ${INDEXER_CONNECTOR_TOOL_SRC})

set_target_properties(
  indexer_connector_tool PROPERTIES RUNTIME_OUTPUT_DIRECTORY
                                    "${CMAKE_BINARY_DIR}/bin")

target_link_libraries(indexer_connector_tool indexer_connector urlrequest)

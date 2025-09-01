cmake_minimum_required(VERSION 3.12.4)

include_directories(../../../headers/)

# Copy input files to the build directory
file(COPY input DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB INDEXER_CONNECTOR_TOOL_SRC
    "*.cpp"
    )

# Add address sanitizer
if(FSANITIZE)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer")
endif()

add_executable(indexer_connector_tool
    ${INDEXER_CONNECTOR_TOOL_SRC}
    )

target_link_libraries(indexer_connector_tool indexer_connector urlrequest)

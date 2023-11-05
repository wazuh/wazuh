cmake_minimum_required(VERSION 3.12.4)

file(GLOB INDEXER_CONNECTOR_TOOL_SRC
    "*.cpp"
    )

# Add address sanitizer
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")

add_executable(indexer_connector_tool
    ${INDEXER_CONNECTOR_TOOL_SRC}
    )

target_link_libraries(indexer_connector_tool indexer_connector urlrequest)


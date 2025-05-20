cmake_minimum_required(VERSION 3.12.4)

file(GLOB INDEXER_CONNECTOR_TOOL_SRC
    "*.cpp"
    )

add_executable(indexer_connector_tool
    ${INDEXER_CONNECTOR_TOOL_SRC}
    )

target_link_libraries(indexer_connector_tool base indexerconnector urlrequest)

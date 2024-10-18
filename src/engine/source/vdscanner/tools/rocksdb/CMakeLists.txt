project(rocksdb_tool)

include_directories(${CMAKE_SOURCE_DIR}/source/base/include)

file(GLOB ROCKSDB_TOOL_SRC
    "*.cpp"
    )

add_executable(${PROJECT_NAME}
    ${ROCKSDB_TOOL_SRC}
    )

target_link_libraries(${PROJECT_NAME} PRIVATE RocksDB::rocksdb flatbuffers::flatbuffers)

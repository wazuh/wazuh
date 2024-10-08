project(rocksdb_testtool)

include_directories(${CMAKE_SOURCE_DIR}/source/base/include)

file(GLOB ROCKS_DB_QUERY_TESTTOOL_SRC
    "*.cpp"
    )

add_executable(${PROJECT_NAME}
    ${ROCKS_DB_QUERY_TESTTOOL_SRC}
    )

target_link_libraries(${PROJECT_NAME} PRIVATE RocksDB::rocksdb flatbuffers::flatbuffers)

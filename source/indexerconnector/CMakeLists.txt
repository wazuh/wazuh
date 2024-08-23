project(indexerconnector)

# Include directories
include_directories(include)

file(GLOB INDEXER_CONNECTOR_SRC
    "src/*.cpp"
    )

add_library(indexerconnector STATIC
    ${INDEXER_CONNECTOR_SRC}
    )
target_include_directories(scan_orchestrator PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(indexerconnector RocksDB::rocksdb base urlrequest)

#add_subdirectory(tool)
#if(UNIT_TEST)
#    add_subdirectory(tests)
#endif()

project(indexerconnector)

# INTERFACE_AUTOMOC_MACRO_NAMES
add_library(indexerconnector_iindexerconnector INTERFACE)
target_include_directories(indexerconnector_iindexerconnector INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
target_link_libraries(indexerconnector_iindexerconnector INTERFACE base)
add_library(indexerconnector::iindexerconnector ALIAS indexerconnector_iindexerconnector)

# Include directories
include_directories(include)

file(GLOB INDEXER_CONNECTOR_SRC
    "src/*.cpp"
    )

add_library(indexerconnector STATIC
    ${INDEXER_CONNECTOR_SRC}
    )
target_include_directories(indexerconnector PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(indexerconnector RocksDB::rocksdb base urlrequest)

add_library(indexerconnector_test INTERFACE)
target_include_directories(indexerconnector_test INTERFACE ${CMAKE_CURRENT_LIST_DIR}/src)
add_library(indexerconnector::test ALIAS indexerconnector_test)

add_subdirectory(tool)
add_subdirectory(test)

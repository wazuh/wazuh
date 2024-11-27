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
target_link_libraries(indexerconnector
  PUBLIC
   indexerconnector::iindexerconnector
  PRIVATE
  RocksDB::rocksdb
  urlrequest
  keystore
)

if(ENGINE_BUILD_TEST)
    # Mocks
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

    add_library(indexerconnector_mocks INTERFACE)
    target_include_directories(indexerconnector_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(indexerconnector_mocks INTERFACE GTest::gmock indexerconnector::iindexerconnector)
    add_library(indexerconnector::mocks ALIAS indexerconnector_mocks)

    add_library(httprequest_mocks INTERFACE)
    target_include_directories(httprequest_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(httprequest_mocks INTERFACE GTest::gmock)
    add_library(httprequest::mock ALIAS httprequest_mocks)
endif()

add_library(indexerconnector_test INTERFACE)
target_include_directories(indexerconnector_test INTERFACE ${CMAKE_CURRENT_LIST_DIR}/src)
add_library(indexerconnector::test ALIAS indexerconnector_test)

add_subdirectory(tool)
add_subdirectory(test)

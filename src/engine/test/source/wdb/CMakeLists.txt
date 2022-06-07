add_executable(wdb_test
    wdb_test.cpp
)

target_include_directories(wdb_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}/wdb/src
    ${TEST_SOURCE_DIR}/base/socketInterface/testAuxiliar/
)

target_link_libraries(wdb_test gtest_main base wdb)
gtest_discover_tests(wdb_test)

add_executable(wdb_DBSync_test
    dbsync_test.cpp
)

target_include_directories(wdb_DBSync_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}/wdb/src
    # TODO Fix this (json/json)
    ${ENGINE_SOURCE_DIR}/json
    # TODO Remove this whens isolate rxcpp from base types
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
)

target_link_libraries(wdb_DBSync_test gtest_main base wdb)
gtest_discover_tests(wdb_DBSync_test)

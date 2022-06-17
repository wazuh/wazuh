add_executable(wdb_test
    ${TEST_SOURCE_DIR}/base/socketInterface/testAuxiliar/socketAuxiliarFunctions.cpp
    wdb_test.cpp
)

target_include_directories(wdb_test
    PRIVATE
    ${ENGINE_SOURCE_DIR}/wdb/src
    ${TEST_SOURCE_DIR}/base/socketInterface/testAuxiliar/
)

target_link_libraries(wdb_test gtest_main base wdb)
gtest_discover_tests(wdb_test)

add_executable(wdb_test
    protocol_test.cpp
)

target_include_directories(wdb_test
    PUBLIC
    ${ENGINE_SOURCE_DIR}/wdb
)

# TODO check if it's ok to add base for the json dep
target_link_libraries(wdb_test gtest_main base)
gtest_discover_tests(wdb_test)

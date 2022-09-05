# Configuration Catalog tests
add_executable(hlp_test
  ${TEST_SOURCE_DIR}/hlp/hlp_test.cpp
)

target_link_libraries(hlp_test hlp gtest_main)

gtest_discover_tests(hlp_test)

# Configuration Catalog tests
add_executable(hlpkvmap_test
  ${TEST_SOURCE_DIR}/hlp/hlpKVMap_test.cpp
)

target_link_libraries(hlpkvmap_test hlp gtest_main)

gtest_discover_tests(hlpkvmap_test)

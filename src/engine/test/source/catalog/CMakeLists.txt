add_executable(catalog_test
  catalog_test.hpp
  catalog_test.cpp
  jsonTestAssets.hpp
)

target_link_libraries(catalog_test gtest_main catalog)
gtest_discover_tests(catalog_test)

add_executable(diskStorageDriverCatalog_test
  storageDriver/disk/diskStorage_test.cpp
)

target_link_libraries(diskStorageDriverCatalog_test gtest_main catalog)
gtest_discover_tests(diskStorageDriverCatalog_test)

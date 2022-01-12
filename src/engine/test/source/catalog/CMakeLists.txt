CPMAddPackage(
  NAME yaml-cpp
  GITHUB_REPOSITORY jbeder/yaml-cpp
  GIT_TAG yaml-cpp-0.7.0
  VERSION 0.7.0
  OPTIONS
      "YAML_BUILD_SHARED_LIBS OFF"
      "YAML_CPP_BUILD_TESTS OFF"
)

CPMAddPackage(
    NAME RapidJSON
    GITHUB_REPOSITORY Tencent/rapidjson
    GIT_TAG v1.1.0
    VERSION 1.1.0
    OPTIONS
        "RAPIDJSON_BUILD_DOC OFF"
        "RAPIDJSON_BUILD_EXAMPLES OFF"
        "RAPIDJSON_BUILD_TESTS OFF"
        # "RAPIDJSON_BUILD_CXX17 ON"
)

# Configuration Catalog tests
add_executable(catalog_test
  ${ENGINE_SOURCE_DIR}/catalog/catalogSharedDef.hpp
  ${ENGINE_SOURCE_DIR}/catalog/yml_to_json.hpp
  ${ENGINE_SOURCE_DIR}/catalog/Catalog.hpp
  ${ENGINE_SOURCE_DIR}/catalog/Catalog.cpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/StorageDriverInterface.hpp
  ${TEST_SOURCE_DIR}/catalog/Catalog_test.hpp
  ${TEST_SOURCE_DIR}/catalog/Catalog_test.cpp
  ${TEST_SOURCE_DIR}/catalog/Catalog_json_assets.hpp
)

target_include_directories(catalog_test PUBLIC "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/")
target_link_libraries(catalog_test gtest_main "yaml-cpp")
gtest_discover_tests(catalog_test)


# Configuration Storage Drivers tests: DiskStorage
add_executable(DiskStorage_driver_catalog_test
  ${ENGINE_SOURCE_DIR}/catalog/catalogSharedDef.hpp
  ${ENGINE_SOURCE_DIR}/catalog/yml_to_json.hpp
  ${ENGINE_SOURCE_DIR}/catalog/Catalog.hpp
  ${ENGINE_SOURCE_DIR}/catalog/Catalog.cpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/StorageDriverInterface.hpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/disk/DiskStorage.hpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/disk/DiskStorage.cpp
  ${TEST_SOURCE_DIR}/catalog/storageDriver/disk/DiskStorage_test.hpp
  ${TEST_SOURCE_DIR}/catalog/storageDriver/disk/DiskStorage_test.cpp
)

target_include_directories(DiskStorage_driver_catalog_test PUBLIC "${ENGINE_SOURCE_DIR}/" "${RapidJSON_SOURCE_DIR}/include/")
target_link_libraries(DiskStorage_driver_catalog_test gtest_main "yaml-cpp")
gtest_discover_tests(DiskStorage_driver_catalog_test)

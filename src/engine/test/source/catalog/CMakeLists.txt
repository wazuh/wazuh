CPMAddPackage(
  NAME yaml-cpp
  GITHUB_REPOSITORY jbeder/yaml-cpp
  GIT_TAG yaml-cpp-0.7.0
  VERSION 0.7.0
  OPTIONS
      "YAML_BUILD_SHARED_LIBS OFF"
      "YAML_CPP_BUILD_TESTS OFF"
)

# Configuration router test
add_executable(diskStorage_driver_catalog_test
  ${ENGINE_SOURCE_DIR}/catalog/catalogSharedDef.hpp
  ${ENGINE_SOURCE_DIR}/catalog/yml2json.hpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/storageDriverInterface.hpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/disk/diskStorage.hpp
  ${ENGINE_SOURCE_DIR}/catalog/storageDriver/disk/diskStorage.cpp
  ${TEST_SOURCE_DIR}/catalog/storageDriver/disk/diskStorage_test.hpp
  ${TEST_SOURCE_DIR}/catalog/storageDriver/disk/diskStorage_test.cpp
)

target_include_directories(diskStorage_driver_catalog_test PUBLIC "${ENGINE_SOURCE_DIR}/")
target_link_libraries(diskStorage_driver_catalog_test gtest_main "yaml-cpp" "nlohmann_json::nlohmann_json")
gtest_discover_tests(diskStorage_driver_catalog_test)

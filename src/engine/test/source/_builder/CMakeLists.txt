# Configuration Catalog tests
add_executable(_builder_test
  #${TEST_SOURCE_DIR}/_builder/registry_test.cpp
  ${ENGINE_SOURCE_DIR}/_builder/builders/operationBuilder.cpp
  ${ENGINE_SOURCE_DIR}/_builder/builders/stageBuilder.cpp
  # ${ENGINE_SOURCE_DIR}/_builder/builders/assetBuilder.cpp
  ${TEST_SOURCE_DIR}/_builder/builder_test.cpp
  ${TEST_SOURCE_DIR}/_builder/event_test.cpp
  ${TEST_SOURCE_DIR}/_builder/expression_test.cpp
)

target_include_directories(_builder_test
  PUBLIC
  ${ENGINE_SOURCE_DIR}
  ${TEST_SOURCE_DIR}/_builder
  ${RxCpp_SOURCE_DIR}/Rx/v2/src
)
target_link_libraries(_builder_test gtest_main base)

gtest_discover_tests(_builder_test)

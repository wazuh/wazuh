set(SHARED_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/base/utils)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
include_directories(${TEST_SOURCE_DIR}/common)

add_executable(stringUtils_test
  stringUtils_test.cpp
  ${SHARED_ENGINE_SOURCE_DIR}/stringUtils.cpp
)

target_link_libraries(stringUtils_test gtest_main base)
gtest_discover_tests(stringUtils_test)

add_executable(ipUtils_test
  ipUtils_test.cpp
  ${SHARED_ENGINE_SOURCE_DIR}/ipUtils.cpp
)

target_link_libraries(ipUtils_test gtest_main base)
gtest_discover_tests(ipUtils_test)

add_executable(result_test
  result_test.cpp
)
target_link_libraries(result_test gtest_main base)
gtest_discover_tests(result_test)

add_executable(logger_test
  logger_test.cpp
)
target_link_libraries(logger_test gtest_main base)
gtest_discover_tests(logger_test)

add_executable(graph_test
graph_test.cpp
)
target_link_libraries(graph_test gtest_main base)
gtest_discover_tests(graph_test)

add_executable(name_test
  name_test.cpp
)
target_link_libraries(name_test gtest_main base)
gtest_discover_tests(name_test)

# Wazuh Protocol test
add_executable(wazuhProtocol_test
  utils/wazuhProtocol/wazuhRequest_test.cpp
  utils/wazuhProtocol/wazuhResponse_test.cpp
)
target_link_libraries(wazuhProtocol_test gtest_main base)
gtest_discover_tests(wazuhProtocol_test)

add_executable(parseEvent_test
  parseEvent_test.cpp
)
target_link_libraries(parseEvent_test gtest_main base)
gtest_discover_tests(parseEvent_test)

add_executable(dotPath_test dotPath_test.cpp)
target_link_libraries(dotPath_test gtest_main base)
gtest_discover_tests(dotPath_test)

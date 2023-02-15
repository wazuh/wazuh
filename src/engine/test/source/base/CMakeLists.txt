set(SHARED_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/base/utils)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
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

add_executable(graph_test
graph_test.cpp
)
target_link_libraries(graph_test gtest_main base)
gtest_discover_tests(graph_test)

add_executable(socketInterface_test
  ${SHARED_ENGINE_SOURCE_DIR}/socketInterface/unixSecureStream.cpp
  ${SHARED_ENGINE_SOURCE_DIR}/socketInterface/unixDatagram.cpp
  socketInterface/testAuxiliar/socketAuxiliarFunctions.cpp
  socketInterface/testAuxiliar/socketAuxiliarFunctions.hpp
  socketInterface/testAuxiliar/socketAuxiliarFunctions_test.cpp
  socketInterface/unixSecureStream_test.cpp
  socketInterface/unixDatagram_test.cpp
)

target_include_directories(socketInterface_test
    PRIVATE
    testAuxiliar/
    ${SHARED_ENGINE_SOURCE_DIR}/socketInterface/
)

target_link_libraries(socketInterface_test gtest_main base)
gtest_discover_tests(socketInterface_test)

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

set(SERVER_TEST_SOURCE_DIR ${TEST_SOURCE_DIR}/server)
set(SERVER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/server)

include_directories(
    ${RapidJSON_SOURCE_DIR}/include/
    ${ENGINE_SOURCE_DIR}
    ${SERVER_ENGINE_SOURCE_DIR}
    ${SERVER_ENGINE_SOURCE_DIR}/endpoints/
    ${SERVER_TEST_SOURCE_DIR}
    ${SERVER_TEST_SOURCE_DIR}/endpoints/
    ${uvw_SOURCE_DIR}/src/
    ${uvw_SOURCE_DIR}/src/uvw/
    ${ENGINE_SOURCE_DIR}/json
)

add_executable(serverTest ${SERVER_ENGINE_SOURCE_DIR}/engineServer.cpp ${SERVER_TEST_SOURCE_DIR}/testsEngineServer.cpp)
target_link_libraries(serverTest gtest_main uv)
gtest_discover_tests(serverTest)

add_executable(tcpTest ${SERVER_TEST_SOURCE_DIR}/endpoints/testsTCPEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/baseEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/tcpEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/protocolHandler.cpp)
target_link_libraries(tcpTest gtest_main uv)
gtest_discover_tests(tcpTest)

add_executable(socketTest ${SERVER_TEST_SOURCE_DIR}/endpoints/testsSocketEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/baseEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/endpoints/socketEndpoint.cpp ${SERVER_ENGINE_SOURCE_DIR}/protocolHandler.cpp)
target_link_libraries(socketTest gtest_main uv)
gtest_discover_tests(socketTest)

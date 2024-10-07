set(ENGINE_SERVER_SOURCE_DIR ${ENGINE_SOURCE_DIR}/server/src)
set(ENGINE_SERVER_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/server/include)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(server STATIC
    ${ENGINE_SERVER_SOURCE_DIR}/engineServer.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoint.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/unixDatagram.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/endpoints/unixStream.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/protocolHandler.cpp
    ${ENGINE_SERVER_SOURCE_DIR}/protocolHandlers/wStream.cpp
)

target_link_libraries(server base libuv::uv_a api queue metrics::imetrics)

target_include_directories(server
    PUBLIC
    ${ENGINE_SERVER_INCLUDE_DIR}
    ${uvw_SOURCE_DIR}/src/
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(server_utest
    ${UNIT_SRC_DIR}/engineServer_test.cpp
    # ${UNIT_SRC_DIR}/unixDatagram_test.cpp
    ${UNIT_SRC_DIR}/unixStream_test.cpp
    ${UNIT_SRC_DIR}/protocolHandlerStream_test.cpp
)

target_include_directories(server_utest
    PRIVATE
    ${uvw_SOURCE_DIR}/src/
)

target_link_libraries(server_utest PRIVATE GTest::gtest_main server libuv::uv_a)
gtest_discover_tests(server_utest)

endif(ENGINE_BUILD_TEST)

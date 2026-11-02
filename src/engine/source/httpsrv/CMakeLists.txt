# SPDX-License-Identifier: AGPL-3.0-or-later
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(httpsrv_ihttpsrv INTERFACE)
target_include_directories(httpsrv_ihttpsrv INTERFACE ${IFACE_DIR})
target_link_libraries(httpsrv_ihttpsrv INTERFACE base)
add_library(httpsrv::ihttpsrv ALIAS httpsrv_ihttpsrv)

# UdsServer runs on the manager's shared HTTP-over-UDS transport. Guarded add_subdirectory, as every
# consumer does, so the engine does not depend on which module registers the target first; asio and
# llhttp stay PRIVATE inside the archive.
if(NOT TARGET wazuh_uds_http_server)
  add_subdirectory(${SHARED_MODULES}/uds_http_server
                   ${CMAKE_BINARY_DIR}/shared_modules/uds_http_server EXCLUDE_FROM_ALL)
endif()

# Under ThreadSanitizer the engine links the transport's instrumented copy (see
# shared_modules/uds_http_server/CMakeLists.txt): with the plain archive TSAN reports false races.
if(ENGINE_ENABLE_TSAN)
  set(HTTPSRV_UDS_TRANSPORT wazuh_uds_http_server_tsan)
else()
  set(HTTPSRV_UDS_TRANSPORT wazuh_uds_http_server)
endif()

add_library(httpsrv STATIC
    ${SRC_DIR}/server.cpp
    ${SRC_DIR}/boundedExecutor.cpp
    ${SRC_DIR}/udsServer.cpp
    ${SRC_DIR}/apiServer.cpp
)
target_include_directories(httpsrv
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${SRC_DIR}
    ${INC_DIR}/httpsrv
)
target_link_libraries(httpsrv
    PUBLIC
    httpsrv::ihttpsrv
    base
    eMessages

    PRIVATE
    ${HTTPSRV_UDS_TRANSPORT}
    fastmetrics::fastmetrics
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(httpsrv_utest
    ${UNIT_SRC_DIR}/server_test.cpp
    ${UNIT_SRC_DIR}/boundedExecutor_test.cpp
    ${UNIT_SRC_DIR}/udsServer_test.cpp
    ${UNIT_SRC_DIR}/udsServerMetrics_test.cpp
    ${UNIT_SRC_DIR}/apiServer_test.cpp
)
target_include_directories(httpsrv_utest
    PRIVATE
    ${TEST_SRC_DIR}
)
target_link_libraries(httpsrv_utest
    PRIVATE
    httpsrv
    fastmetrics::fastmetrics
    GTest::gtest_main
)
gtest_discover_tests(httpsrv_utest)

add_executable(httpsrv_ctest
    ${COMPONENT_SRC_DIR}/server_test.cpp
    ${TEST_SRC_DIR}/generic_request.pb.cc
)
target_include_directories(httpsrv_ctest
    PRIVATE
    ${TEST_SRC_DIR}
)
target_link_libraries(httpsrv_ctest
    PRIVATE
    httpsrv
    GTest::gtest_main
    base::test
)
gtest_discover_tests(httpsrv_ctest)

endif()

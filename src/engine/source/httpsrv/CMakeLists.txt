set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(httpsrv_ihttpsrv INTERFACE)
target_include_directories(httpsrv_ihttpsrv INTERFACE ${IFACE_DIR})
target_link_libraries(httpsrv_ihttpsrv INTERFACE base)
add_library(httpsrv::ihttpsrv ALIAS httpsrv_ihttpsrv)

add_library(httpsrv STATIC
    ${SRC_DIR}/server.cpp
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
    httplib::httplib
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(httpsrv_utest
    ${UNIT_SRC_DIR}/server_test.cpp
    ${UNIT_SRC_DIR}/protoHelper_test.cpp
    ${TEST_SRC_DIR}/generic_request.pb.cc
)
target_include_directories(httpsrv_utest
    PRIVATE
    ${TEST_SRC_DIR}
)
target_link_libraries(httpsrv_utest
    PRIVATE
    httpsrv
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

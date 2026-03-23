set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_adapter INTERFACE)
target_include_directories(api_adapter
    INTERFACE
    ${INC_DIR}
)
target_link_libraries(api_adapter
    INTERFACE
    base
    httpsrv
    eMessages
)
add_library(api::adapter ALIAS api_adapter)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UTEST_SRC_DIR ${TEST_SRC_DIR}/unit)
    set(TEST_INC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/include)

    add_executable(api_adapter_utest
        ${UTEST_SRC_DIR}/adapter_test.cpp
        ${TEST_SRC_DIR}/generic_request.pb.cc
    )
    target_include_directories(api_adapter_utest
        PRIVATE
        ${TEST_SRC_DIR}
    )
    target_link_libraries(api_adapter_utest
        PRIVATE
        api::adapter
        GTest::gtest_main
    )
    gtest_discover_tests(api_adapter_utest)

    add_library(api_adapter_test INTERFACE)
    target_include_directories(api_adapter_test INTERFACE ${TEST_INC_DIR})
    target_link_libraries(api_adapter_test
        INTERFACE
        api::adapter
        GTest::gtest
        base::test
    )
    add_library(api::adapter::test ALIAS api_adapter_test)

endif()

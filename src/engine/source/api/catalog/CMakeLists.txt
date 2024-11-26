set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(api_catalog_icatalog INTERFACE)
target_include_directories(api_catalog_icatalog INTERFACE ${IFACE_DIR})
target_link_libraries(api_catalog_icatalog INTERFACE base eMessages builder::ibuilder store::istore)
add_library(api::catalog::icatalog ALIAS api_catalog_icatalog)

add_library(api_catalog STATIC
  ${SRC_DIR}/catalog.cpp
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_catalog
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_catalog
    PUBLIC
    base
    api::catalog::icatalog
    api::adapter

    PRIVATE
    yml
)
add_library(api::catalog ALIAS api_catalog)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_library(api_catalog_mocks INTERFACE)
    target_include_directories(api_catalog_mocks INTERFACE ${TEST_MOCK_DIR})
    target_link_libraries(api_catalog_mocks INTERFACE api::catalog::icatalog GTest::gmock)
    add_library(api::catalog::mocks ALIAS api_catalog_mocks)


    add_executable(api_catalog_utest
        ${UNIT_SRC_DIR}/resource_test.cpp
        ${UNIT_SRC_DIR}/catalog_test.cpp
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_catalog_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_catalog_utest
        PRIVATE
        api::catalog
        api::catalog::mocks
        GTest::gtest_main
        builder::mocks
        store::mocks
        api::adapter::test
    )
    gtest_discover_tests(api_catalog_utest)
endif()

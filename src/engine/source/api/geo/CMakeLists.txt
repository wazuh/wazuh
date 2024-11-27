set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_geo STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_geo
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_geo
    PUBLIC
    api::adapter
    geo::igeo
)
add_library(api::geo ALIAS api_geo)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_geo_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_geo_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_geo_utest
        PRIVATE
        api::geo
        geo::mocks
        GTest::gtest_main
        api::adapter::test
    )
    gtest_discover_tests(api_geo_utest)
endif()

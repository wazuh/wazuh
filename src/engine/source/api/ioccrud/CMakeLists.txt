set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_ioccrud STATIC
  ${SRC_DIR}/handlersSync.cpp
)
target_include_directories(api_ioccrud
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_ioccrud
    PUBLIC
    api::adapter
    iockvdb::ikvdb
    scheduler::ischeduler
    store::istore
)
add_library(api::ioccrud ALIAS api_ioccrud)


if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_ioccrud_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_ioccrud_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_ioccrud_utest
        PRIVATE
        api::ioccrud
        GTest::gtest_main
        api::adapter::test
        iockvdb::mocks
        scheduler::mocks
        store::mocks
    )
    gtest_discover_tests(api_ioccrud_utest)
endif()

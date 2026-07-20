set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_rawevtindexer STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_rawevtindexer
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_rawevtindexer
    PUBLIC
    api::adapter
    rawevtindexer::irawindexer
)
add_library(api::rawevtindexer ALIAS api_rawevtindexer)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_rawevtindexer_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_rawevtindexer_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_rawevtindexer_utest
        PRIVATE
        api::rawevtindexer
        GTest::gtest_main
        api::adapter::test
        rawevtindexer::mocks
    )
    gtest_discover_tests(api_rawevtindexer_utest)
endif()

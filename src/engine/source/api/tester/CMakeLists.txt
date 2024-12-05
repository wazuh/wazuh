set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_tester STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_tester
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_tester
    PUBLIC
    base
    api::adapter
    router::irouter
    api::policy::ipolicy
)
add_library(api::tester ALIAS api_tester)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_tester_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_tester_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_tester_utest
        PRIVATE
        api::tester
        GTest::gtest_main
        router::mocks
        api::adapter::test
    )
    gtest_discover_tests(api_tester_utest)
endif()

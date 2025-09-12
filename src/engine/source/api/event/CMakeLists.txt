set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_event STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_event
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_event
    PUBLIC
    api::adapter
    router::irouter
    archiver::iface
)
add_library(api::event ALIAS api_event)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_event_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
        ${UNIT_SRC_DIR}/ndJsonParser_test.cpp
    )
    target_include_directories(api_event_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_event_utest
        PRIVATE
        api::event
        router::mocks
        GTest::gtest_main
        api::adapter::test
        archiver::mocks
    )
    gtest_discover_tests(api_event_utest)
endif()

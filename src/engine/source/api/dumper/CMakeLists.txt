set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_dumper STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_dumper
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_dumper
    PUBLIC
    api::adapter
    dumper::iface
)
add_library(api::dumper ALIAS api_dumper)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_dumper_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_dumper_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_dumper_utest
        PRIVATE
        api::dumper
        GTest::gtest_main
        api::adapter::test
        dumper::mocks
    )
    gtest_discover_tests(api_dumper_utest)
endif()

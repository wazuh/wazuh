set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_archiver STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_archiver
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_archiver
    PUBLIC
    api::adapter
    archiver::iface
)
add_library(api::archiver ALIAS api_archiver)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_archiver_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_include_directories(api_archiver_utest
        PRIVATE
        ${UNIT_SRC_DIR}
    )
    target_link_libraries(api_archiver_utest
        PRIVATE
        api::archiver
        GTest::gtest_main
        api::adapter::test
        archiver::mocks
    )
    gtest_discover_tests(api_archiver_utest)
endif()

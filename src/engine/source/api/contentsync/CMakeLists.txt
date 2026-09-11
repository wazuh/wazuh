set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_contentsync STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_contentsync
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_contentsync
    PUBLIC
    api::adapter
    cmsync::icmsync
    iocsync::iiocsync
)
add_library(api::contentsync ALIAS api_contentsync)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_contentsync_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_link_libraries(api_contentsync_utest
        PRIVATE
        api::contentsync
        cmsync::mocks
        iocsync::mocks
        GTest::gtest_main
        GTest::gmock
        eMessages
    )
    gtest_discover_tests(api_contentsync_utest)
endif()

set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_status STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_status
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_status
    PUBLIC
    api::adapter
    cmsync::icmsync
    iocsync::iiocsync
    geo::igeo
)
add_library(api::status ALIAS api_status)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_status_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_link_libraries(api_status_utest
        PRIVATE
        api::status
        cmsync::mocks
        iocsync::mocks
        geo::mocks
        GTest::gtest_main
        GTest::gmock
        eMessages
    )
    gtest_discover_tests(api_status_utest)
endif()

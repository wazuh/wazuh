# SPDX-License-Identifier: AGPL-3.0-or-later
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_metrics STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_metrics
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_metrics
    PUBLIC
    api::adapter
    fastmetrics::fastmetrics
)
add_library(api::metrics ALIAS api_metrics)

if(ENGINE_BUILD_TEST)
    set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
    set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

    add_executable(api_metrics_utest
        ${UNIT_SRC_DIR}/handlers_test.cpp
    )
    target_link_libraries(api_metrics_utest
        PRIVATE
        api::metrics
        GTest::gtest_main
    )
    gtest_discover_tests(api_metrics_utest)
endif()

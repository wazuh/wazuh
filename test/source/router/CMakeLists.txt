# Router test
add_executable(router_test
  ${TEST_SOURCE_DIR}/router/router_test.cpp
)
target_link_libraries(router_test engine_test_main base router builders)
gtest_discover_tests(router_test)

# Router + rxkb test
add_executable(rxbk_router_test
  ${TEST_SOURCE_DIR}/router/rxbk_router_test.cpp
)
target_link_libraries(rxbk_router_test engine_test_main base router builders rxbk)
gtest_discover_tests(rxbk_router_test)

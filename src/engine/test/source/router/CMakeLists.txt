####################################################################################################
# Sources -- Headers -- Libraries
####################################################################################################
add_executable(routerTest
  ${TEST_SOURCE_DIR}/router/routerTest.cpp
)

target_include_directories(routerTest PUBLIC
  ${ENGINE_SOURCE_DIR}/json
  ${ENGINE_SOURCE_DIR}/router
)

# TODO is it ok to link to base here only for json?
target_link_libraries(routerTest gtest_main rxcpp base)
gtest_discover_tests(routerTest)

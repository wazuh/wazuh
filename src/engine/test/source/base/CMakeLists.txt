set(SHARED_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/base/utils)

####################################################################################################
# Builder targets
####################################################################################################
# Builder test
add_executable(stringUtils_test
  stringUtils_test.cpp
  ${SHARED_ENGINE_SOURCE_DIR}/stringUtils.cpp
)

target_link_libraries(stringUtils_test gtest_main base)
gtest_discover_tests(stringUtils_test)

add_executable(ipUtils_test
  ipUtils_test.cpp
  ${SHARED_ENGINE_SOURCE_DIR}/ipUtils.cpp
)

target_link_libraries(ipUtils_test gtest_main base)
gtest_discover_tests(ipUtils_test)

add_executable(result_test
  result_test.cpp
)
target_link_libraries(result_test gtest_main base)
gtest_discover_tests(result_test)

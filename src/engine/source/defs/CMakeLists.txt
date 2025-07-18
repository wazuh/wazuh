add_library(defs_idefinitions INTERFACE)
target_include_directories(defs_idefinitions INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/interface
)
target_link_libraries(defs_idefinitions INTERFACE base)
add_library(defs::idefinitions ALIAS defs_idefinitions)


add_library(defs STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/defs.cpp
)
target_include_directories(defs
PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/include
PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/src
  ${CMAKE_CURRENT_LIST_DIR}/include/defs
)
target_link_libraries(defs defs::idefinitions base)

if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

# Testing mocks
add_library(defs_mocks INTERFACE)
target_include_directories(defs_mocks INTERFACE ${TEST_MOCK_DIR}
)
target_link_libraries(defs_mocks INTERFACE defs::idefinitions)
add_library(defs::mocks ALIAS defs_mocks)

add_executable(defs_utest
  ${UNIT_SRC_DIR}/defs_test.cpp
)
target_include_directories(defs_utest
  PRIVATE
  ${TEST_SRC_DIR}
  ${CMAKE_CURRENT_LIST_DIR}/src
  ${CMAKE_CURRENT_LIST_DIR}/include/defs
)

target_link_libraries(defs_utest
  PRIVATE
  defs::mocks
  defs
  GTest::gmock_main
)

gtest_discover_tests(defs_utest)

endif(ENGINE_BUILD_TEST)

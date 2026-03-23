# Dirs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# API CM CRUD library
add_library(api_cmcrud STATIC
  ${SRC_DIR}/handlers.cpp
)

target_include_directories(api_cmcrud
  PUBLIC
    ${INC_DIR}
  PRIVATE
    ${SRC_DIR}
)

target_link_libraries(api_cmcrud
  PUBLIC
    base
    api::adapter
    router::irouter
    cmcrud::icmcrud
)

add_library(api::cmcrud ALIAS api_cmcrud)

# Tests
if(ENGINE_BUILD_TEST)

  set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
  set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

  add_executable(api_cmcrud_utest
    ${UNIT_SRC_DIR}/handlers_test.cpp
  )

  target_include_directories(api_cmcrud_utest
    PRIVATE
      ${UNIT_SRC_DIR}
  )

  target_link_libraries(api_cmcrud_utest
    PRIVATE
      api::cmcrud
      GTest::gtest_main
      cmcrud::mocks
      api::adapter::test
  )

  gtest_discover_tests(api_cmcrud_utest)

endif()

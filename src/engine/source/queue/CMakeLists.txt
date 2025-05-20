# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/test)

# # Interface
add_library(queue_iqueue INTERFACE)
target_include_directories(queue_iqueue INTERFACE ${IFACE_DIR})
target_link_libraries(queue_iqueue INTERFACE base)
add_library(queue::iqueue ALIAS queue_iqueue)

# # Queue
add_library(queue STATIC
  ${SRC_DIR}/concurrentQueue.cpp)

# target_link_libraries(queue
target_include_directories(queue
  PUBLIC
  ${INC_DIR}
  ${CameronQueue_SOURCE_DIR}
)

target_link_libraries(queue
  PUBLIC
  base # Only for the loggin
  queue::iqueue
  unofficial-concurrentqueue::concurrentqueue
  metrics::imetrics
)

# Tests
if(ENGINE_BUILD_TEST)
  set(TEST_SRC_DIR ${TEST_DIR}/src)
  set(TEST_SRC_COMPONENT_DIR ${TEST_SRC_DIR}/component)
  set(TEST_SRC_UNIT_DIR ${TEST_SRC_DIR}/unit)
  set(TEST_MOCK_DIR ${TEST_DIR}/mocks)

  # Mocks
  add_library(queue_mocks INTERFACE)
  target_include_directories(queue_mocks INTERFACE ${TEST_MOCK_DIR})
  target_link_libraries(queue_mocks INTERFACE GTest::gmock queue)
  add_library(queue::mocks ALIAS queue_mocks)

  # Component test
  add_executable(queue_ctest
    ${TEST_SRC_COMPONENT_DIR}/queue_test.cpp
  )

  target_link_libraries(queue_ctest
    GTest::gtest_main
    base
    queue
    metrics::mocks
    base::test
  )
  gtest_discover_tests(queue_ctest)

endif(ENGINE_BUILD_TEST)

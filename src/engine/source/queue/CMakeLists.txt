# Concurrent Queue
CPMAddPackage(
  NAME CameronQueue
  GITHUB_REPOSITORY cameron314/concurrentqueue
  GIT_TAG v1.0.3
  VERSION 1.0.3
  EXCLUDE_FROM_ALL YES
)

add_library(queue STATIC
  src/concurrentQueue.cpp)

# target_link_libraries(queue
target_include_directories(queue
  PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CameronQueue_SOURCE_DIR}
)

cmake_minimum_required(VERSION 3.12.4)

project(container_connector_impl CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/shared/include
  ${SRC_FOLDER}/shared_modules/http-request/include
  ${SRC_FOLDER}/shared_modules/utils
  ${SRC_FOLDER}/external/nlohmann
  ${SRC_FOLDER}/external/curl/include/curl
)

file(GLOB CONTAINER_CONNECTOR_IMPL_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(CONTAINER_CONNECTOR_IMPL STATIC ${CONTAINER_CONNECTOR_IMPL_SRC})

target_include_directories(CONTAINER_CONNECTOR_IMPL PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(CONTAINER_CONNECTOR_IMPL PUBLIC urlrequest)

set_target_properties(CONTAINER_CONNECTOR_IMPL PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(CONTAINER_CONNECTOR_IMPL)
endif()

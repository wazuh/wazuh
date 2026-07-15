cmake_minimum_required(VERSION 3.12.4)

project(container_baseline_impl CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS
    "-Wall -Wextra -Wshadow -Wnon-virtual-dtor -Woverloaded-virtual -Wunused -Wcast-align -Wformat=2 -pthread"
)

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${SRC_FOLDER}/shared/include
  ${SRC_FOLDER}/external/nlohmann
  ${SRC_FOLDER}/external/openssl/include
  ${SRC_FOLDER}/wazuh_modules/container_connector/include
)

link_directories(${SRC_FOLDER}/external/openssl/)

file(GLOB CONTAINER_BASELINE_IMPL_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")

add_library(CONTAINER_BASELINE_IMPL STATIC ${CONTAINER_BASELINE_IMPL_SRC})

target_include_directories(CONTAINER_BASELINE_IMPL PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(CONTAINER_BASELINE_IMPL PUBLIC container_connector wazuhext)

set_target_properties(CONTAINER_BASELINE_IMPL PROPERTIES
  POSITION_INDEPENDENT_CODE ON
)

if(UNIT_TEST)
  enable_testing()
  add_coverage_libraries(CONTAINER_BASELINE_IMPL)
  add_subdirectory(tests)
endif()

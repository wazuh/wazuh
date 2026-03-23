cmake_minimum_required(VERSION 3.12.4)

project(router_benchmark_tests)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(${SRC_FOLDER}/external/benchmark/include/)

file(GLOB SOURCES *.cpp)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} benchmark router)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

set_tests_properties(${PROJECT_NAME} PROPERTIES LABELS "router")

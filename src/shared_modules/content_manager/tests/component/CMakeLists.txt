cmake_minimum_required(VERSION 3.12.4)

project(content_manager_component_tests)

file(GLOB PROJECT_SOURCES
    *.cpp
    ${CMAKE_SOURCE_DIR}/content_manager/src/*[!main]*.cpp
)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

target_link_libraries(${PROJECT_NAME}
    gtest
    gtest_main
    gmock
    urlrequest
    router
)

target_link_libraries(${PROJECT_NAME} content_manager)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

cmake_minimum_required(VERSION 3.12.4)

project(content_manager_unit_tests)

# Copy input files to the build directory
file(COPY input_files DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

file(GLOB PROJECT_SOURCES
    *.cpp
    ${CMAKE_SOURCE_DIR}/content_manager/src/*[!main]*.cpp
)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

target_link_libraries(${PROJECT_NAME}
    debug gtestd
    debug gmockd
    optimized gtest
    optimized gmock
    urlrequest
    router
    wazuhext
    lzma
    rocksdb
    pthread
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

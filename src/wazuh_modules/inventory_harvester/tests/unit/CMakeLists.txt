cmake_minimum_required(VERSION 3.12.4)

project(harvester_unit_tests)

set(CMAKE_CXX_FLAGS_DEBUG "-g --coverage -fsanitize=address,leak,undefined")

include_directories(${SRC_FOLDER}/external/flatbuffers/include/)

file(GLOB PROJECT_SOURCES
    *.cpp
    ${SRC_FOLDER}/inventory_harvester/src/*[!main]*.cpp
    ${SRC_FOLDER}/inventory_harvester/src/common/*.cpp
    ${SRC_FOLDER}/inventory_harvester/src/fimInventory/*.cpp
    ${SRC_FOLDER}/inventory_harvester/src/systemInventory/*.cpp
    ${SRC_FOLDER}/inventory_harvester/src/wcsModel/*.cpp
    ${SRC_FOLDER}/inventory_harvester/src/wcsModel/wcsClasses/*.cpp
)

link_directories(${SRC_FOLDER}/external/rocksdb/build)
link_directories(${SRC_FOLDER}/external/flatbuffers/build/)
link_directories(${SRC_FOLDER}/external/curl/lib/.libs/)

add_executable(${PROJECT_NAME} ${PROJECT_SOURCES})

target_link_libraries(${PROJECT_NAME}
    debug gtestd
    debug gmockd
    debug gtest_maind
    debug gmock_maind
    optimized gtest
    optimized gmock
    optimized gtest_main
    optimized gmock_main
    flatbuffers
    rocksdb
    router
    urlrequest
    curl
    pthread
)

target_link_libraries(${PROJECT_NAME} inventory_harvester)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

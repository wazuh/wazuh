cmake_minimum_required(VERSION 3.12.4)
project(urlrequest)

include_directories(src/)
include_directories(include/)
link_directories(${SRC_FOLDER}/external/curl/lib/.libs/)

file(GLOB URL_REQUEST_SRC src/*.cpp)

add_library(urlrequest ${URL_REQUEST_SRC})

target_link_libraries(urlrequest curl)

add_subdirectory(test_tool)
add_subdirectory(test)

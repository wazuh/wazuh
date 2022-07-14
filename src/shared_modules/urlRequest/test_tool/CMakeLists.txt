cmake_minimum_required(VERSION 3.12.4)
project(urlrequest_testtool)

include_directories(src/)

file(GLOB URL_REQUEST_SRC *.cpp)

add_executable(urlrequest_testtool ${URL_REQUEST_SRC})

target_link_libraries(urlrequest_testtool urlrequest)


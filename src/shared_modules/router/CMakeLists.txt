cmake_minimum_required(VERSION 3.12.4)

project(router)

enable_testing()

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

#add include directory
include_directories(include)

file(GLOB ROUTER_SRC
    "src/*.cpp"
    )

add_library(router SHARED
    ${ROUTER_SRC}
    )

add_subdirectory(testtool)
add_subdirectory(tests)

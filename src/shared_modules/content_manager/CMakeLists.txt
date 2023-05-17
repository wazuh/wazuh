cmake_minimum_required(VERSION 3.12.4)

project(content_manager)

enable_testing()

include_directories(include)
include_directories(${SRC_FOLDER}/shared_modules)

file(GLOB CONTENT_DOWNLOAD_SRC
    "src/*.cpp"
    )

add_library(content_manager SHARED
    ${CONTENT_DOWNLOAD_SRC}
    )

target_link_libraries(content_manager router)

add_subdirectory(testtool)

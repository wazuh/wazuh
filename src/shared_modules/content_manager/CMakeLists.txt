cmake_minimum_required(VERSION 3.12.4)

project(content_manager)

enable_testing()

include_directories(include)
include_directories(${SRC_FOLDER}/shared_modules)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/tests)
include_directories(${SRC_FOLDER}/shared_modules/content_manager/src/components)

file(GLOB CONTENT_DOWNLOAD_SRC
    "src/*.cpp"
    )

add_library(content_manager SHARED
    ${CONTENT_DOWNLOAD_SRC}
    )

target_link_libraries(content_manager router urlrequest gcc_s)

set_target_properties(content_manager PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
add_subdirectory(tests)

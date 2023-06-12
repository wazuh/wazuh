cmake_minimum_required(VERSION 3.12.4)

project(indexer_connector)

enable_testing()

add_definitions(-DPROMISE_TYPE=PromiseType::NORMAL)

#add include directory
include_directories(include)

file(GLOB INDEXER_CONNECTOR_SRC
    "src/*.cpp"
    )

add_library(indexer_connector SHARED
    ${INDEXER_CONNECTOR_SRC}
    )

target_link_libraries(indexer_connector rocksdb gcc_s)

set_target_properties(indexer_connector PROPERTIES
        BUILD_RPATH_USE_ORIGIN TRUE
        BUILD_RPATH "$ORIGIN/../lib"
)

add_subdirectory(testtool)
#add_subdirectory(tests)

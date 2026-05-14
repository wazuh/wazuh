cmake_minimum_required(VERSION 3.12.4)

if(FSANITIZE)
set(CMAKE_CXX_FLAGS_DEBUG "-g -fsanitize=address,leak,undefined")
endif()

file(GLOB VD_SCANNER_TESTTOOL_SRC
    "*.cpp"
    )

add_executable(inventory_harvester_testtool
    ${VD_SCANNER_TESTTOOL_SRC}
    )

target_link_libraries(inventory_harvester_testtool inventory_harvester rocksdb router indexer_connector)

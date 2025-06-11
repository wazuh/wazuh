cmake_minimum_required(VERSION 3.12.4)
project(inventory_sync_testtool)

file(GLOB INVENTORY_SYNC_TESTTOOL_SRC
    "*.cpp"
    )

add_executable(inventory_sync_testtool ${INVENTORY_SYNC_TESTTOOL_SRC})

target_link_libraries(inventory_sync_testtool inventory_sync rocksdb router indexer_connector)

set(ENGINE_WDB_SOURCE_DIR ${ENGINE_SOURCE_DIR}/wdb/src)
set(ENGINE_WDB_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/wdb/include)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(wdb STATIC
    ${ENGINE_WDB_SOURCE_DIR}/wdb.cpp
)


target_link_libraries(wdb PRIVATE base)

target_include_directories(wdb
    PRIVATE
    ${ENGINE_WDB_SOURCE_DIR}
    # TODO Fix this (json/json)
    ${ENGINE_SOURCE_DIR}/json
    # TODO Remove this whens isolate rxcpp from base types
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
    PUBLIC
    ${ENGINE_WDB_INCLUDE_DIR}
)

set(ENGINE_WDB_SOURCE_DIR ${ENGINE_SOURCE_DIR}/wdb/src)
set(ENGINE_WDB_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/wdb/include)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(wdb STATIC
    ${ENGINE_WDB_SOURCE_DIR}/protocol.hpp
)

target_include_directories(wdb
    PRIVATE
    #TODO fix this?
    ${ENGINE_SOURCE_DIR}/json
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(wdb base)

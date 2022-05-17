
####################################################################################################
# Sources - Includes
####################################################################################################
add_library(wdb OBJECT
    protocol.hpp
)

target_include_directories(wdb
    PRIVATE
    #TODO fix this?
    ${ENGINE_SOURCE_DIR}/json
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
)

target_link_libraries(wdb base)

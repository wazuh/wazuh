set(ENGINE_HLP3_SOURCE_DIR ${ENGINE_SOURCE_DIR}/hlp3/src)
set(ENGINE_HLP3_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/hlp3/include)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(hlp3 STATIC
        # Header
#        ${ENGINE_HLP3_INCLUDE_DIR}/parser.hpp
#        ${ENGINE_HLP3_INCLUDE_DIR}/hlp3.hpp
        # Source
        ${ENGINE_HLP3_SOURCE_DIR}/hlp3.cpp

)

#TODO do this better
target_link_libraries(hlp3 json)

target_include_directories(hlp3
    PUBLIC
    ${ENGINE_HLP3_INCLUDE_DIR}
)

set(ENGINE_HLP_SOURCE_DIR ${ENGINE_SOURCE_DIR}/hlp/src)
set(ENGINE_HLP_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/hlp/include)
set(ENGINE_HLP_TOOLS_DIR ${ENGINE_SOURCE_DIR}/hlp/tools)

####################################################################################################
# Dependencies
####################################################################################################
# TODO we use the one from the system. We may want to change this
find_package(CURL REQUIRED)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(hlp STATIC
    ${ENGINE_HLP_SOURCE_DIR}/hlp.cpp
    ${ENGINE_HLP_SOURCE_DIR}/hlpDetails.hpp
    ${ENGINE_HLP_SOURCE_DIR}/hlpDetails.cpp
    ${ENGINE_HLP_SOURCE_DIR}/LogQLParser.cpp
    ${ENGINE_HLP_SOURCE_DIR}/LogQLParser.hpp
    ${ENGINE_HLP_SOURCE_DIR}/SpecificParsers.hpp
    ${ENGINE_HLP_SOURCE_DIR}/SpecificParsers.cpp
    ${ENGINE_HLP_SOURCE_DIR}/date/date.h
)

target_link_libraries(hlp 
    PUBLIC base
    PRIVATE CURL::libcurl)

target_include_directories(hlp
    PUBLIC ${ENGINE_HLP_INCLUDE_DIR}
)

####################################################################################################
# Test tool
####################################################################################################

add_executable(hlp_cli
  ${ENGINE_HLP_TOOLS_DIR}/hlp_cli.cpp
)

target_link_libraries(hlp_cli yaml-cpp hlp base)

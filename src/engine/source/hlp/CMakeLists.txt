####################################################################################################
# Dependencies
####################################################################################################
# TODO we use the one from the system. We may want to change this
find_package(CURL REQUIRED)

add_compile_definitions ( ONLY_C_LOCALE=1 )

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(hlp STATIC
    src/hlp.cpp
    src/hlpDetails.hpp
    src/hlpDetails.cpp
    src/logQLParser.cpp
    src/logQLParser.hpp
    src/specificParsers.hpp
    src/specificParsers.cpp
    src/date/date.h
)

target_link_libraries(hlp 
    PUBLIC base
    PRIVATE CURL::libcurl)

target_include_directories(hlp
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
)

####################################################################################################
# Test tool
####################################################################################################

add_executable(hlpCli
    tools/hlpCli.cpp
)

target_link_libraries(hlpCli yaml-cpp hlp base)

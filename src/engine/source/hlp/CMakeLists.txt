####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
    NAME CURL
    GITHUB_REPOSITORY curl/curl
    GIT_TAG curl-7_85_0
    VERSION 7.85.0
    EXCLUDE_FROM_ALL YES
    DOWNLOAD_ONLY
)

add_compile_definitions ( ONLY_C_LOCALE=1 )

CPMAddPackage(
  NAME pugixml
  GITHUB_REPOSITORY zeux/pugixml
  GIT_TAG v1.12.1
  VERSION 1.12.1
)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(hlp STATIC
    src/date/date.h
    src/hlp.cpp
    src/hlpDetails.cpp
    src/hlpDetails.hpp
    src/logParser.cpp
    src/logParser.hpp
    src/specificParsers.cpp
    src/specificParsers.hpp
)

target_link_libraries(hlp
    PUBLIC base
    PRIVATE CURL::libcurl pugixml)

target_include_directories(hlp
    PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include
)

####################################################################################################
# Test tool
####################################################################################################
set(THREADS_PREFER_PTHREAD_FLAG ON)

add_executable(hlpCli
    tools/hlpCli.cpp
)

find_package(Threads REQUIRED)

target_link_libraries(hlpCli PUBLIC yaml-cpp hlp base PRIVATE Threads::Threads)

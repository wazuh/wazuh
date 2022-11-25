CPMAddPackage(
        NAME date
        GITHUB_REPOSITORY HowardHinnant/date
        GIT_TAG v3.0.1
        VERSION 3.0.1
        OPTIONS
        "AUTO_DOWNLOAD 1"
)

CPMAddPackage(
        NAME fmt
        GITHUB_REPOSITORY fmtlib/fmt
        GIT_TAG "8.1.1"
)

CPMAddPackage(
        NAME csv
        GITHUB_REPOSITORY vincentlaucsb/csv-parser
        VERSION 2.1.3
        GIT_TAG 2.1.3
)

CPMAddPackage(
        NAME CURL
        GITHUB_REPOSITORY curl/curl
        GIT_TAG curl-7_85_0
        VERSION 7.85.0
        EXCLUDE_FROM_ALL YES
        DOWNLOAD_ONLY
)

add_library(hlp_parsec INTERFACE)
target_include_directories(hlp_parsec INTERFACE ${CMAKE_CURRENT_LIST_DIR}/parsec/include/)
add_library(hlp::parsec ALIAS hlp_parsec)

add_library(hlp2 STATIC
        src/basic.cpp
        src/basic.hpp
        src/web.cpp
        src/file.cpp
        src/json.cpp
        src/xml.cpp
        src/csv.cpp
        src/kvmap.cpp
        src/logpar.cpp
        ${date_SOURCE_DIR}/src/tz.cpp
)

# https://github.com/HowardHinnant/date/wiki/FAQ#why-is-a-failing
add_definitions(-DONLY_C_LOCALE)

# https://howardhinnant.github.io/date/tz.html#Installation
#
# You may have to use -lpthread. If you're getting a mysterious crash on first access to the database, it is likely that
# you aren't linking to the pthread library. The pthread library is used to assure that that library initialization
# is thread safe in a multithreaded environment.
target_link_libraries(hlp2 base pugixml hlp::parsec date::date CURL::libcurl csv "--coverage" json pthread)

target_include_directories(hlp2
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        PRIVATE
        ${csv_SOURCE_DIR}/include
)


CPMAddPackage(
        NAME CURL
        GITHUB_REPOSITORY curl/curl
        GIT_TAG curl-7_83_1
        VERSION 7.83_1
        EXCLUDE_FROM_ALL YES
        GIT_SHALLOW TRUE
        DOWNLOAD_ONLY
)

CPMAddPackage(
        NAME date
        GITHUB_REPOSITORY HowardHinnant/date
        GIT_TAG v3.0.1
        VERSION 3.0.1
        GIT_SHALLOW TRUE
        OPTIONS
        "AUTO_DOWNLOAD 1"
)

CPMAddPackage(
        NAME fast_float
        GITHUB_REPOSITORY fastfloat/fast_float
        VERSION 3.8.0
        GIT_SHALLOW TRUE
)

add_library(hlp_parsec INTERFACE)
target_include_directories(hlp_parsec INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/parsec/include/)

add_library(hlp2 STATIC
        src/number.cpp
        src/number.hpp
        src/web.cpp
        src/file.cpp
        src/json.cpp
        src/xml.cpp
        src/csv.cpp
        src/kvmap.cpp
        ${date_SOURCE_DIR}/src/tz.cpp
        src/stream_view.hpp
        src/parse_field.hpp
        src/date.cpp
        src/parse_field.cpp
        src/bool.cpp
        src/ip.cpp
        src/text.cpp
        src/encodings.cpp
        src/logpar.cpp
        src/base.hpp
        src/literal.cpp)

# src/stop.hpp)

# https://github.com/HowardHinnant/date/wiki/FAQ#why-is-a-failing
add_compile_definitions(ONLY_C_LOCALE=1)

# add_definitions(-DONLY_C_LOCALE)

# https://howardhinnant.github.io/date/tz.html#Installation
#
# You may have to use -lpthread. If you're getting a mysterious crash on first access to the database, it is likely that
# you aren't linking to the pthread library. The pthread library is used to assure that that library initialization
# is thread safe in a multithreaded environment.
target_link_libraries(hlp2
        PUBLIC base hlp_parsec
        PRIVATE
        pugixml
        date::date
        CURL::libcurl
        fast_float
        json
        pthread)

target_include_directories(hlp2
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        PRIVATE
        ${csv_SOURCE_DIR}/include
)

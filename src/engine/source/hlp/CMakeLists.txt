
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
        # Live at head
        # https://github.com/HowardHinnant/date/issues/828#issuecomment-2184283807
        GITHUB_REPOSITORY HowardHinnant/date
        GIT_TAG 1ead6715dec030d340a316c927c877a3c4e5a00c
        OPTIONS
        "AUTO_DOWNLOAD 0"
        "HAS_REMOTE_API 1"
)

CPMAddPackage(
        NAME fast_float
        GITHUB_REPOSITORY fastfloat/fast_float
        VERSION 3.8.0
        GIT_SHALLOW TRUE
)

CPMAddPackage(
  NAME pugixml
  GITHUB_REPOSITORY zeux/pugixml
  GIT_TAG v1.12.1
  VERSION 1.12.1
)

# https://github.com/HowardHinnant/date/wiki/FAQ#why-is-a-failing
# This works with glibc 2.28-211.el8 RHEL 8
# add_compile_definitions(ONLY_C_LOCALE=1)

# https://howardhinnant.github.io/date/tz.html#Installation
#
# You may have to use -lpthread. If you're getting a mysterious crash on first access to the database, it is likely that
# you aren't linking to the pthread library. The pthread library is used to assure that that library initialization
# is thread safe in a multithreaded environment.
add_library(hlp STATIC
  src/parsers/literal.cpp
  src/parsers/text.cpp
  src/parsers/eof.cpp
  src/parsers/number.cpp
  src/parsers/alphanumeric.cpp
  src/parsers/bool.cpp
  src/parsers/between.cpp
  src/parsers/date.cpp
  ${date_SOURCE_DIR}/src/tz.cpp
  src/parsers/encodings.cpp
  src/parsers/json.cpp
  src/parsers/ip.cpp
  src/parsers/ignore.cpp
  src/parsers/xml.cpp
  src/parsers/quoted.cpp
  src/parsers/file.cpp
  src/parsers/web.cpp
  src/parsers/parse_field.cpp
  src/parsers/kvmap.cpp
  src/parsers/dsv_csv.cpp
)
target_include_directories(hlp
PUBLIC
  include/
PRIVATE
  src/
  src/parsers/
  include/hlp/
)
target_link_libraries(hlp PUBLIC base PRIVATE fast_float date::date pthread CURL::libcurl pugixml)

# For the date library
target_compile_definitions(hlp PRIVATE AUTO_DOWNLOAD=0 HAS_REMOTE_API=1)

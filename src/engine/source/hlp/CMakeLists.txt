add_library(hlp STATIC
  src/parsers/literal.cpp
  src/parsers/text.cpp
  src/parsers/eof.cpp
  src/parsers/number.cpp
  src/parsers/alphanumeric.cpp
  src/parsers/bool.cpp
  src/parsers/between.cpp
  src/parsers/date.cpp
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
target_link_libraries(hlp PUBLIC base PRIVATE FastFloat::fast_float date::date date::date-tz pthread CURL::libcurl pugixml)


# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)

add_executable(hlp_utest
  ${UNIT_SRC_DIR}/hlp_test.cpp
  ${UNIT_SRC_DIR}/text_test.cpp
  ${UNIT_SRC_DIR}/literal_test.cpp
  ${UNIT_SRC_DIR}/numeric_test.cpp
  ${UNIT_SRC_DIR}/eof_test.cpp
  ${UNIT_SRC_DIR}/alnum_test.cpp
  ${UNIT_SRC_DIR}/bool_test.cpp
  ${UNIT_SRC_DIR}/between_test.cpp
  ${UNIT_SRC_DIR}/date_test.cpp
  ${UNIT_SRC_DIR}/binary_test.cpp
  ${UNIT_SRC_DIR}/json_test.cpp
  ${UNIT_SRC_DIR}/ip_test.cpp
  ${UNIT_SRC_DIR}/ignore_test.cpp
  ${UNIT_SRC_DIR}/xml_test.cpp
  ${UNIT_SRC_DIR}/quoted_test.cpp
  ${UNIT_SRC_DIR}/file_test.cpp
  ${UNIT_SRC_DIR}/web_test.cpp
  ${UNIT_SRC_DIR}/kvmap_test.cpp
  ${UNIT_SRC_DIR}/dsv_csv_test.cpp
)

target_link_libraries(hlp_utest PRIVATE hlp GTest::gtest_main)
gtest_discover_tests(hlp_utest)

endif(ENGINE_BUILD_TEST)

add_executable(hlp_test
  hlp_test.cpp
  text_test.cpp
  literal_test.cpp
  numeric_test.cpp
  eof_test.cpp
  alnum_test.cpp
  bool_test.cpp
  between_test.cpp
  date_test.cpp
  binary_test.cpp
  json_test.cpp
  ip_test.cpp
  ignore_test.cpp
  xml_test.cpp
  quoted_test.cpp
  file_test.cpp
  web_test.cpp
  kvmap_test.cpp
  dsv_csv_test.cpp
)

target_link_libraries(hlp_test hlp gtest_main)
gtest_discover_tests(hlp_test)

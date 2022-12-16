add_executable(parsec_test
    parsec_test.cpp
)
target_link_libraries(parsec_test hlp::parsec gtest_main)
gtest_discover_tests(parsec_test)

add_executable(logpar_test
    logpar_test.cpp
)
target_link_libraries(logpar_test hlp::logpar hlp_parsec gtest_main)
gtest_discover_tests(logpar_test)

add_executable(hlp2_test
        basic_test.cpp
        between_test.cpp
        binary_test.cpp
        date_test.cpp
        dsv_csv_test.cpp
        file_test.cpp
        ignore_test.cpp
        ip_test.cpp
        json_test.cpp
        kvmap_test.cpp
        quoted_test.cpp
        run_test.hpp
        web_test.cpp
        xml_test.cpp
)

target_include_directories(hlp2_test
        PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/include
        PRIVATE
        ${ENGINE_SOURCE_DIR}/json/include
        ${ENGINE_SOURCE_DIR}/hlp2/include
)

target_link_libraries(hlp2_test hlp2 hlp_parsec gtest_main)
gtest_discover_tests(hlp2_test)


add_executable(parsec_test
    parsec_test.cpp
)
target_link_libraries(parsec_test hlp2 hlp_parsec gtest_main)
gtest_discover_tests(parsec_test)

add_executable(hlp2_test
        run_test.hpp
        basic_test.cpp
        web_test.cpp
        file_test.cpp
        json_test.cpp
        xml_test.cpp
        csv_test.cpp
        kbmap_test.cpp
        date_test.cpp
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

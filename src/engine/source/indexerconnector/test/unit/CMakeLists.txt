project(indexerconnector_utest)

file(GLOB SOURCES
        *.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        indexerconnector::test
        httprequest::mock
        urlrequest
        GTest::gtest_main
        GTest::gmock_main
        pthread
        base
)

gtest_discover_tests(${PROJECT_NAME})

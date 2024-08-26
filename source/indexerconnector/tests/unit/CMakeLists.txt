project(indexer_connector_unit_tests)

file(GLOB SOURCES
        *.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        indexerconnector::test
        urlrequest
        GTest::gtest_main
        pthread
        base
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

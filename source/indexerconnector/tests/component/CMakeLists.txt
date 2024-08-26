project(indexer_connector_component_tests)

file(GLOB SOURCES
        *.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        urlrequest
        GTest::gtest_main
        indexerconnector
        pthread
        base
)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

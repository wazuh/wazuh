project(indexerconnector_utest)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../mocks/)

file(GLOB SOURCES
        *.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME}
        indexerconnector::test
        urlrequest
        GTest::gtest_main
        GTest::gmock_main
        pthread
        base
)

gtest_discover_tests(${PROJECT_NAME})

project(indexerconnector_ctest)

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

gtest_discover_tests(${PROJECT_NAME})

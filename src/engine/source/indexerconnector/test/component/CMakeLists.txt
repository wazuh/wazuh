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

target_link_options(${PROJECT_NAME} PRIVATE -Wl,--wrap=getpwnam,--wrap=getgrnam,--wrap=chown)

gtest_discover_tests(${PROJECT_NAME})

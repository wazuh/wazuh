add_dependencies(${PROJECT_NAME} dbsyncPipelineFactory_unit_test)
project(dbsyncPipelineFactory_unit_test)

file(GLOB PIPELINE_FACTORY_UNITTEST_SRC
    "*.cpp")

file(GLOB PIPELINE_FACTORY_SRC
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/sqlite/*.cpp")

add_executable(dbsyncPipelineFactory_unit_test
    ${PIPELINE_FACTORY_UNITTEST_SRC}
    ${PIPELINE_FACTORY_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbsyncPipelineFactory_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        sqlite3
        cjson
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(dbsyncPipelineFactory_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        sqlite3
        cjson
        dl
    )
endif()

add_test(NAME dbsyncPipelineFactory_unit_test
    COMMAND dbsyncPipelineFactory_unit_test)

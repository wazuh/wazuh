add_dependencies(${PROJECT_NAME} dbengine_unit_test)
project(dbengine_unit_test)

file(GLOB DBENGINE_UNITTEST_SRC
    "*.cpp")

file(GLOB SQLITE_ENGINE_SRC
    "${CMAKE_SOURCE_DIR}/shared_modules/dbsync/src/sqlite/sqlite_dbengine.cpp")

add_executable(dbengine_unit_test
    ${DBENGINE_UNITTEST_SRC}
    ${SQLITE_ENGINE_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(dbengine_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(dbengine_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        dl
    )
endif()

add_test(NAME dbengine_unit_test
    COMMAND dbengine_unit_test)

project(sys_normalizer_unit_test)

file(GLOB SYS_NORMALIZER_UNIT_TEST_SRC
    "*.cpp")

file(GLOB SYS_NORMALIZER_SRC
    "${CMAKE_SOURCE_DIR}/wazuh_modules/syscollector/src/syscollectorNormalizer.cpp")

add_definitions(-DWAZUH_UNIT_TESTING)

add_executable(sys_normalizer_unit_test
    ${SYS_NORMALIZER_UNIT_TEST_SRC}
    ${SYS_NORMALIZER_SRC})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_link_libraries(sys_normalizer_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        -static-libgcc -static-libstdc++
    )
else()
    target_link_libraries(sys_normalizer_unit_test
        gtest
        gmock
        gtest_main
        gmock_main
        pthread
        dl
    )
endif()

add_test(NAME sys_normalizer_unit_test
         COMMAND sys_normalizer_unit_test)

set(BUILDER_ENGINE_SOURCE_DIR ${ENGINE_SOURCE_DIR}/builder)

add_executable(rxFactory_test
    ${CMAKE_CURRENT_LIST_DIR}/rxFactory_test.cpp
    ${BUILDER_ENGINE_SOURCE_DIR}/asset.cpp
    ${BUILDER_ENGINE_SOURCE_DIR}/policy.cpp
    ${BUILDER_ENGINE_SOURCE_DIR}/registry.cpp
    ${BUILDER_ENGINE_SOURCE_DIR}/definitions.cpp
)
target_link_libraries(rxFactory_test gtest_main rxbk)
gtest_discover_tests(rxFactory_test)

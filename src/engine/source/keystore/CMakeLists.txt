cmake_minimum_required(VERSION 3.12.4)

project(keystore)

enable_testing()

file(GLOB KEYSTORE_SRC
    "src/keyStore.cpp"
    )

add_subdirectory(tools)

add_library(keystore STATIC ${KEYSTORE_SRC})
target_link_libraries(keystore PRIVATE base)
target_include_directories(keystore PUBLIC include)

add_executable(wazuh-keystore src/main.cpp)
target_link_libraries(wazuh-keystore keystore OpenSSL::SSL OpenSSL::Crypto RocksDB::rocksdb base -static-libgcc -static-libstdc++)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/tests)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(keystore_ctest
    ${COMPONENT_SRC_DIR}/keyStoreComponent_test.cpp
)
target_link_libraries(keystore_ctest GTest::gtest_main keystore OpenSSL::SSL OpenSSL::Crypto RocksDB::rocksdb base)
gtest_discover_tests(keystore_ctest)

endif(ENGINE_BUILD_TEST)

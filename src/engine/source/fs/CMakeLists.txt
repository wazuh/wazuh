project(filesystem)

enable_testing()

####################################################################################################
# FS
####################################################################################################
# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(fs_ifs INTERFACE)
target_include_directories(fs_ifs INTERFACE ${IFACE_DIR})
add_library(fs::ifs ALIAS fs_ifs)

add_library(${PROJECT_NAME} STATIC
    ${SRC_DIR}/archiveHelper.cpp
    ${SRC_DIR}/xzHelper.cpp
    ${SRC_DIR}/hashHelper.cpp
)
target_include_directories(${PROJECT_NAME}
    PUBLIC
    ${INC_DIR}

    PRIVATE
    ${INC_DIR}/xz
    ${SRC_DIR}
)
target_link_libraries(${PROJECT_NAME}
    PUBLIC
    fs::ifs
    PRIVATE
    liblzma::liblzma
    LibArchive::LibArchive
)

# Tests
if(ENGINE_BUILD_TEST)
    set(TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/test)
    set(TEST_SRC_DIR ${TEST_DIR}/src)
    set(INPUT_FILES ${TEST_DIR}/input_files)

    file(COPY ${INPUT_FILES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

    add_executable(${PROJECT_NAME}_utest
        ${TEST_SRC_DIR}/archiveHelper_test.cpp
        ${TEST_SRC_DIR}/hashHelper_test.cpp
        ${TEST_SRC_DIR}/xzHelper_test.cpp
    )

    target_link_libraries(${PROJECT_NAME}_utest
        PRIVATE
        ${PROJECT_NAME}
        GTest::gtest_main
        RocksDB::rocksdb
        CURL::libcurl
        filesystem
    )
    gtest_discover_tests(${PROJECT_NAME}_utest)
endif(ENGINE_BUILD_TEST)

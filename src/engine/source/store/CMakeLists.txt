# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(store_istore INTERFACE)
target_include_directories(store_istore INTERFACE ${IFACE_DIR})
target_link_libraries(store_istore INTERFACE fmt base json)
add_library(store::istore ALIAS store_istore)

add_library(store_fileDriver STATIC
    ${CMAKE_CURRENT_LIST_DIR}/drivers/fileDriver/src/fileDriver.cpp
)
target_include_directories(store_fileDriver
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/drivers/fileDriver/include
)
target_link_libraries(store_fileDriver store::istore)
add_library(store::fileDriver ALIAS store_fileDriver)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_library(store_mocks INTERFACE)
target_include_directories(store_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(store_mocks INTERFACE gmock store::istore)
add_library(store::mocks ALIAS store_mocks)

endif(ENGINE_BUILD_TEST)

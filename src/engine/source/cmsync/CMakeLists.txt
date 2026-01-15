# Defs
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

# INTERFACE
add_library(cmsync_icmsync INTERFACE)
target_include_directories(cmsync_icmsync INTERFACE ${IFACE_DIR})
target_link_libraries(cmsync_icmsync INTERFACE base)
add_library(cmsync::icmsync ALIAS cmsync_icmsync)

# Implementation
add_library(cmsync_cmsync STATIC
    ${SRC_DIR}/cmsync.cpp
)
target_include_directories(cmsync_cmsync
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(cmsync_cmsync
    PUBLIC
    base
    cmsync::icmsync
    cmcrud::icmcrud
    store::istore
    router::irouter
    wIndexerConnector::iwIndexerConnector
)
add_library(cmsync::cmsync ALIAS cmsync_cmsync)

# # Tests
# if(ENGINE_BUILD_TEST)
# 
# set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
# set(UNIT_SRC_DIR ${TEST_SRC_DIR}/unit)
# set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)
# set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)
# 
# # Mocks
# add_library(cmsync_mocks INTERFACE)
# target_include_directories(cmsync_mocks INTERFACE ${TEST_MOCK_DIR})
# target_link_libraries(cmsync_mocks INTERFACE GTest::gmock cmsync::icmsync)
# add_library(cmsync::mocks ALIAS cmsync_mocks)
# 
# 
# add_executable(cmsync_utest
#     ${UNIT_SRC_DIR}/cmsync_test.cpp
#     ${UNIT_SRC_DIR}/cachens_test.cpp
#     ${UNIT_SRC_DIR}/storecti_test.cpp
# )
# target_link_libraries(cmsync_utest
#     PRIVATE
#     GTest::gtest_main
#     GTest::gmock
#     cmsync::cmsync
#     ctistore::mocks
# )
# target_include_directories(cmsync_utest PRIVATE ${SRC_DIR})
# gtest_discover_tests(cmsync_utest)
# 
# add_executable(cmsync_ctest
#     ${COMPONENT_SRC_DIR}/cmsync_test.cpp
#     ${COMPONENT_SRC_DIR}/storecti_test.cpp
# )
# 
# target_link_libraries(cmsync_ctest
#     PRIVATE
#     cmsync::cmsync
#     GTest::gtest_main
#     GTest::gmock
#     ctistore::mocks
# )
# target_include_directories(cmsync_ctest PRIVATE ${SRC_DIR})
# gtest_discover_tests(cmsync_ctest)
# 
# endif(ENGINE_BUILD_TEST)

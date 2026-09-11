set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

####################################################################################################
# Sources - Objects
####################################################################################################
add_library(cmcontent_cmcontent STATIC
    ${SRC_DIR}/registration.cpp
    ${SRC_DIR}/contentTopic.cpp
    ${SRC_DIR}/engineTokenStore.cpp
    ${SRC_DIR}/iocTypeSink.cpp
    ${SRC_DIR}/rulesetSink.cpp
)
target_include_directories(cmcontent_cmcontent
    PUBLIC
    ${INC_DIR}
)
target_link_libraries(cmcontent_cmcontent
    PUBLIC
    base
    store::istore
    cmcrud::icmcrud
    router::irouter
    iockvdb::ikvdb
    # content_manager is a SHARED library built outside the engine tree, and it is PUBLIC here
    # because this target's own public headers name its types: iocTypeSink.hpp and rulesetSink.hpp
    # both implement IContentSink, and cmsync/iocsync hold ContentRegister members. A consumer that
    # cannot see contentSink.hpp cannot include ours.
    #
    # Note the ABI consequence this makes explicit rather than hides: wazuh-engine links libstdc++
    # statically while content_manager.so links it dynamically, so the contract crosses that
    # boundary by value only and never throws across it. See contentSink.hpp.
    content_manager
)
add_library(cmcontent::cmcontent ALIAS cmcontent_cmcontent)

####################################################################################################
# Tests
####################################################################################################
if(ENGINE_BUILD_TEST)

# Mocks: the fake topic registry, shared with cmsync_utest and iocsync_utest. Both drive their
# orchestration through it, which is the only way to exercise that code without a live indexer.
add_library(cmcontent_mocks INTERFACE)
target_include_directories(cmcontent_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(cmcontent_mocks INTERFACE GTest::gmock cmcontent::cmcontent)
add_library(cmcontent::mocks ALIAS cmcontent_mocks)

set(TEST_TARGET_NAME cmcontent_utest)

add_executable(${TEST_TARGET_NAME}
    ${TEST_SRC_DIR}/unit/registration_test.cpp
    ${TEST_SRC_DIR}/unit/contentTopic_test.cpp
    ${TEST_SRC_DIR}/unit/engineTokenStore_test.cpp
    ${TEST_SRC_DIR}/unit/iocTypeSink_test.cpp
    ${TEST_SRC_DIR}/unit/rulesetSink_test.cpp
)
target_include_directories(${TEST_TARGET_NAME}
    PRIVATE
    ${TEST_SRC_DIR}
    ${TEST_MOCK_DIR}
)
target_link_libraries(${TEST_TARGET_NAME}
    PRIVATE
    cmcontent::cmcontent
    iockvdb::mocks
    cmcrud::mocks
    router::mocks
    GTest::gtest_main
    GTest::gmock
)
gtest_discover_tests(${TEST_TARGET_NAME})

endif(ENGINE_BUILD_TEST)

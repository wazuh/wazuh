# Defs
set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(sockiface_isock INTERFACE)
target_include_directories(sockiface_isock INTERFACE ${IFACE_DIR})
add_library(sockiface::isock ALIAS sockiface_isock)

add_library(sockiface STATIC
  ${SRC_DIR}/unixInterface.cpp
  ${SRC_DIR}/unixDatagram.cpp
  ${SRC_DIR}/unixSecureStream.cpp
)
target_include_directories(sockiface
PUBLIC
  ${INC_DIR}
PRIVATE
  ${SRC_DIR}
  ${INC_DIR}/sockiface
)
target_link_libraries(sockiface PUBLIC sockiface::isock PRIVATE base)

# Tests
if(ENGINE_BUILD_TEST)
set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(TEST_MOCK_DIR ${CMAKE_CURRENT_LIST_DIR}/test/mocks)

add_library(sockiface_mocks INTERFACE)
target_include_directories(sockiface_mocks INTERFACE ${TEST_MOCK_DIR})
target_link_libraries(sockiface_mocks INTERFACE GTest::gmock sockiface::isock)
add_library(sockiface::mocks ALIAS sockiface_mocks)

add_executable(sockiface_test
  ${TEST_SRC_DIR}/unixDatagram_test.cpp
  ${TEST_SRC_DIR}/unixSecureStream_test.cpp
  ${TEST_SRC_DIR}/testAuxiliar/socketAuxiliarFunctions.cpp
  ${TEST_SRC_DIR}/testAuxiliar/socketAuxiliarFunctions.hpp
  ${TEST_SRC_DIR}/testAuxiliar/socketAuxiliarFunctions_test.cpp
)

target_include_directories(sockiface_test
    PRIVATE
    ${TEST_SRC_DIR}/testAuxiliar/
)

target_link_libraries(sockiface_test GTest::gtest_main base sockiface)
gtest_discover_tests(sockiface_test)
endif(ENGINE_BUILD_TEST)

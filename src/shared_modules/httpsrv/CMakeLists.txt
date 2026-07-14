cmake_minimum_required(VERSION 3.12.4)

project(httpsrv)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

if(NOT DEFINED SHARED_MODULES)
  get_filename_component(SHARED_MODULES ${SRC_FOLDER}/shared_modules/ ABSOLUTE)
endif()

set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(sm_httpsrv_iface INTERFACE)
target_include_directories(sm_httpsrv_iface INTERFACE ${IFACE_DIR})
add_library(sm_httpsrv::iface ALIAS sm_httpsrv_iface)

add_library(sm_httpsrv STATIC
    ${SRC_DIR}/server.cpp
)

target_include_directories(sm_httpsrv
    PUBLIC
    ${INC_DIR}
    ${SRC_FOLDER}/external/cpp-httplib

    PRIVATE
    ${SRC_DIR}
    ${INC_DIR}/httpsrv
    ${SRC_FOLDER}/shared/include
    ${SHARED_MODULES}/utils
)

target_link_libraries(sm_httpsrv
    PUBLIC
    sm_httpsrv::iface
    pthread
)

set_property(TARGET sm_httpsrv PROPERTY POSITION_INDEPENDENT_CODE ON)

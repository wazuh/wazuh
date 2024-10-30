set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)
set(IFACE_DIR ${CMAKE_CURRENT_LIST_DIR}/interface)

add_library(httpsrv_ihttpsrv INTERFACE)
target_include_directories(httpsrv_ihttpsrv INTERFACE ${IFACE_DIR})
target_link_libraries(httpsrv_ihttpsrv INTERFACE base)
add_library(httpsrv::ihttpsrv ALIAS httpsrv_ihttpsrv)

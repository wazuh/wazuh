add_library(conf_iconf INTERFACE)
target_include_directories(conf_iconf INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
add_library(conf::iconf ALIAS conf_iconf)

add_library(conf_cliconf STATIC
    src/cliconf.cpp
)
target_include_directories(conf_cliconf
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/include
    ${CLI11_SOURCE_DIR}/include
)
target_link_libraries(conf_cliconf base)
add_library(conf::cliconf ALIAS conf_cliconf)

add_library(conf INTERFACE)
target_link_directories(conf INTERFACE conf::iconf conf::cliconf)

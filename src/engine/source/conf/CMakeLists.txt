add_library(conf_interface INTERFACE)
target_include_directories(conf_interface INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
add_library(conf::iconf ALIAS conf_interface)

# add_library(conf_cliconf STATIC
#     src/config.cpp
# )
# target_include_directories(conf_cliconf
#     PUBLIC
#     ${CMAKE_CURRENT_LIST_DIR}/include
#     PRIVATE
#     ${CLI11_SOURCE_DIR}/include
# )
# target_link_libraries(conf_cliconf conf::iconf)
# add_library(conf::cliconf ALIAS conf_cliconf)

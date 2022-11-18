add_library(hlp_parsec INTERFACE)
target_include_directories(hlp_parsec INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/parsec/include/)
add_library(hlp::parsec ALIAS hlp_parsec)

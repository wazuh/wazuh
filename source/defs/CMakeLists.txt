add_library(defs_idefinition INTERFACE)
target_include_directories(defs_idefinition INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/interface/include
)
target_link_libraries(defs_idefinition INTERFACE json)
add_library(defs::idefinition ALIAS defs_idefinition)


add_library(defs STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/defs.cpp
)
target_include_directories(defs
PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/include
PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/src
  ${CMAKE_CURRENT_LIST_DIR}/include/defs
)
target_link_libraries(defs defs::idefinition json base)

add_library(defs_idefinitions INTERFACE)
target_include_directories(defs_idefinitions INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/interface
)
target_link_libraries(defs_idefinitions INTERFACE json)
add_library(defs::idefinitions ALIAS defs_idefinitions)


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
target_link_libraries(defs defs::idefinitions json base)

# Testing mocks
add_library(defs_mocks INTERFACE)
target_include_directories(defs_mocks INTERFACE
  ${CMAKE_CURRENT_LIST_DIR}/mocks
  ${CMAKE_CURRENT_LIST_DIR}/test/mocks
)
target_link_libraries(defs_mocks INTERFACE defs::idefinitions)
add_library(defs::mocks ALIAS defs_mocks)

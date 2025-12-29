add_library(shared INTERFACE)
add_library(api::shared ALIAS shared)

target_include_directories(shared INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)

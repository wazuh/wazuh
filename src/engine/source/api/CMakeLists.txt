add_subdirectory(adapter)
add_subdirectory(geo)
add_subdirectory(router)
add_subdirectory(tester)
add_subdirectory(kvdb)
add_subdirectory(event)
add_subdirectory(archiver)
add_subdirectory(cmcrud)

add_library(api INTERFACE)
target_include_directories(api INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(api INTERFACE
  api::geo
  api::router
  api::tester
  api::kvdb
  api::event
  api::archiver
  api::cmcrud
)

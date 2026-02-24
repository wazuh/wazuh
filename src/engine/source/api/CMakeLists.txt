add_subdirectory(adapter)
add_subdirectory(geo)
add_subdirectory(router)
add_subdirectory(tester)
add_subdirectory(archiver)
add_subdirectory(rawevtindexer)
add_subdirectory(event)
add_subdirectory(cmcrud)
add_subdirectory(shared)

add_library(api INTERFACE)
target_include_directories(api INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(api INTERFACE
  api::geo
  api::router
  api::tester
  api::event
  api::archiver
  api::cmcrud
  api::rawevtindexer
)

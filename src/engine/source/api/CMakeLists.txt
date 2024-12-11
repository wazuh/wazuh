add_subdirectory(adapter)
add_subdirectory(catalog)
add_subdirectory(geo)
add_subdirectory(policy)
add_subdirectory(router)
add_subdirectory(tester)
add_subdirectory(kvdb)
add_subdirectory(event)

add_library(api INTERFACE)
target_include_directories(api INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(api INTERFACE
  api::catalog
  api::geo
  api::policy
  api::router
  api::tester
  api::kvdb
  api::event
)

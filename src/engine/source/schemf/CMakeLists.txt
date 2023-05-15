add_library(schemf_ischema INTERFACE)
target_include_directories(schemf_ischema INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
target_link_libraries(schemf_ischema INTERFACE json base)
add_library(schemf::ischema ALIAS schemf_ischema)

add_library(schemf STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/schema.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/field.cpp
)

target_include_directories(schemf
PUBLIC
  ${CMAKE_CURRENT_LIST_DIR}/include
PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/src
  ${CMAKE_CURRENT_LIST_DIR}/include/schemf
)
target_link_libraries(schemf schemf::ischema)

add_library(schemf_mocks INTERFACE)
target_include_directories(schemf_mocks INTERFACE ${CMAKE_CURRENT_LIST_DIR}/mocks)
target_link_libraries(schemf_mocks INTERFACE schemf::ischema)
add_library(schemf::mocks ALIAS schemf_mocks)

set(SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
set(INC_DIR ${CMAKE_CURRENT_LIST_DIR}/include)

add_library(api_metrics STATIC
  ${SRC_DIR}/handlers.cpp
)
target_include_directories(api_metrics
  PUBLIC
  ${INC_DIR}
  PRIVATE
  ${SRC_DIR}
)
target_link_libraries(api_metrics
    PUBLIC
    api::adapter
    fastmetrics::fastmetrics
)
add_library(api::metrics ALIAS api_metrics)

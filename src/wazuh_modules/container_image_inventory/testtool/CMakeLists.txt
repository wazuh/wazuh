add_executable(container-image-inventory-poc main.cpp)

target_link_libraries(container-image-inventory-poc PRIVATE container_image_inventory_lib)

set_target_properties(container-image-inventory-poc PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")

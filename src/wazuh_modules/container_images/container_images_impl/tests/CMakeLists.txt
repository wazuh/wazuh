if(NOT DEFINED WAZUH_MAIN_PROJECT)
  get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
endif()

include_directories(
  ${SRC_FOLDER}/external/googletest/googletest/include/
  ${SRC_FOLDER}/external/googletest/googlemock/include/
  ${SRC_FOLDER}/external/nlohmann/
  ${SRC_FOLDER}/wazuh_modules/container_images/container_images_impl/include
  ${SRC_FOLDER}/wazuh_modules/container_images/container_images_impl/src)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

link_libraries(
  debug
  gtestd
  debug
  gmockd
  debug
  gtest_maind
  debug
  gmock_maind
  optimized
  gtest
  optimized
  gmock
  optimized
  gtest_main
  optimized
  gmock_main)

add_executable(container_images_unit_test container_images_test.cpp)
target_link_libraries(container_images_unit_test PRIVATE ContainerImagesImpl)
add_test(NAME ContainerImagesTest COMMAND container_images_unit_test)

set_tests_properties(ContainerImagesTest PROPERTIES LABELS "container_images")

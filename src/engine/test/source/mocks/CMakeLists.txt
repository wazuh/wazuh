add_library(test_mocks INTERFACE)
target_include_directories(test_mocks INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(test_mocks INTERFACE metrics api store_fileDriver)

# ###################################################################################################
# Sources - Includes
# ###################################################################################################
add_library(store_interface INTERFACE)
target_include_directories(store_interface INTERFACE ${CMAKE_CURRENT_LIST_DIR}/interface)
target_link_libraries(store_interface INTERFACE base)

add_library(store_fileDriver STATIC
    ${CMAKE_CURRENT_LIST_DIR}/drivers/fileDriver/src/fileDriver.cpp
)

target_include_directories(store_fileDriver
    PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/drivers/fileDriver/include
)

target_link_libraries(store_fileDriver store_interface)

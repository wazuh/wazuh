cmake_minimum_required(VERSION 3.12.4)

project(task_manager_testtool CXX)

add_executable(task_manager_testtool ${CMAKE_CURRENT_LIST_DIR}/main.cpp)

set_target_properties(task_manager_testtool PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON
                                                       CXX_EXTENSIONS OFF
                                                       RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
                                                       BUILD_RPATH_USE_ORIGIN TRUE
                                                       BUILD_RPATH "$ORIGIN/../lib")

target_include_directories(
  task_manager_testtool PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
                                ${SRC_FOLDER}/shared_modules/common
                                ${SRC_FOLDER}/external/cJSON)

target_link_libraries(task_manager_testtool task_manager pthread)

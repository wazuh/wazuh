include_directories(wrappers)

add_subdirectory(groups)
add_subdirectory(users)
if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  add_subdirectory(browser_extensions)
endif()

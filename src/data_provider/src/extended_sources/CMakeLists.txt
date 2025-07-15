include_directories(wrappers)

add_subdirectory(groups)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    add_subdirectory(services)
endif()
add_subdirectory(users)

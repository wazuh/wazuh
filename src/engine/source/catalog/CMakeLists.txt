####################################################################################################
# Dependencies
####################################################################################################
# yaml-cpp::yaml-cpp vs yaml-cpp #FIXME 70 stars on github
CPMAddPackage(
  NAME yaml-cpp
  GITHUB_REPOSITORY jbeder/yaml-cpp
  GIT_TAG yaml-cpp-0.7.0
  VERSION 0.7.0
  OPTIONS
      "YAML_BUILD_SHARED_LIBS OFF"
      "YAML_CPP_BUILD_TESTS OFF"
  EXCLUDE_FROM_ALL YES
)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(catalog OBJECT
    catalog.cpp
    assetStorage/diskStorage.cpp
)

target_include_directories(catalog 
    PUBLIC
    .
    assetStorage/
)

target_link_libraries(catalog base yaml-cpp)

set(ENGINE_CATALOG_SOURCE_DIR ${ENGINE_SOURCE_DIR}/catalog)

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
target_sources(main PRIVATE
    ${ENGINE_CATALOG_SOURCE_DIR}/Catalog.cpp
    ${ENGINE_CATALOG_SOURCE_DIR}/storageDriver/disk/DiskStorage.cpp
    ${ENGINE_CATALOG_SOURCE_DIR}/catalogSharedDef.cpp
)

target_include_directories(main PUBLIC
    ${rapidjson_SOURCE_DIR}/include
    ${ENGINE_CATALOG_SOURCE_DIR}
    ${ENGINE_CATALOG_SOURCE_DIR}/storageDriver/
    ${ENGINE_CATALOG_SOURCE_DIR}/storageDriver/disk/
)

#TODO do this better
target_link_libraries(main yaml-cpp)

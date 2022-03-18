####################################################################################################
# Dependencies
####################################################################################################
CPMAddPackage(
  NAME argparse
  GITHUB_REPOSITORY p-ranav/argparse
  GIT_TAG v2.2
  VERSION 2.2
  DOWNLOAD_ONLY YES
)
####################################################################################################
# Sources - Includes
####################################################################################################
target_sources(main 
    PRIVATE cliParser.cpp
)

target_include_directories(main 
    PUBLIC .
    PRIVATE ${argparse_SOURCE_DIR}/include
)

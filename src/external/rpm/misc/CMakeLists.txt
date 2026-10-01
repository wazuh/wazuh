add_library(libmisc OBJECT fts.c rpmfts.h)
target_include_directories(libmisc PRIVATE ${Intl_INCLUDE_DIRS})

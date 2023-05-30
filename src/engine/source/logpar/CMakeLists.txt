add_library(logpar STATIC src/logpar.cpp)
target_include_directories(logpar
PUBLIC
  include
PRIVATE
  include/logpar
)
target_link_libraries(logpar PUBLIC hlp fmt json)

cmake_minimum_required(VERSION 3.12.4)

project(fim_recovery)

enable_testing()

# Add tests subdirectory when building unit tests
if(UNIT_TEST)
  add_subdirectory(tests)
endif(UNIT_TEST)

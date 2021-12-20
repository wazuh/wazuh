# dependencies
CPMAddPackage(
  NAME RxCpp
  GITHUB_REPOSITORY ReactiveX/RxCpp
  GIT_TAG v4.1.1
  VERSION 4.1.1
  OPTIONS
    "MAKE_BUILD_TYPE RelWithDebInfo"
)

list(APPEND EXTERNAL_DEPS "rxcpp")
set(EXTERNAL_DEPS ${EXTERNAL_DEPS} PARENT_SCOPE)

# sources
set(SANDBOX_SOURCES
    sandbox.cpp
    sandbox.hpp
    environment.cpp
    environment.hpp
)

target_sources(main PRIVATE ${SANDBOX_SOURCES})

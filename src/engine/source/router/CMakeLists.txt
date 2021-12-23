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
set(ROUTER_SOURCES
    router.cpp
    router.hpp
)

target_sources(main PRIVATE ${ROUTER_SOURCES})

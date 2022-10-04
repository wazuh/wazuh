# #########################################################################################
# Dependencies
# #########################################################################################
CPMAddPackage(
    NAME RxCpp
    GITHUB_REPOSITORY ReactiveX/RxCpp
    GIT_TAG v4.1.1
    VERSION 4.1.1
    OPTIONS
    "RXCPP_DISABLE_TESTS_AND_EXAMPLES"
    EXCLUDE_FROM_ALL YES
    DOWNLOAD_ONLY
)

# ########################################################################################
# Lib
# ########################################################################################
add_library(rxbk STATIC
    src/rxFactory.cpp
)

target_include_directories(rxbk
    PUBLIC
    ${RxCpp_SOURCE_DIR}/Rx/v2/src
    ${ENGINE_SOURCE_DIR}/base
    ${ENGINE_SOURCE_DIR}/json
    ${ENGINE_SOURCE_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/include
)

target_link_libraries(rxbk PUBLIC base json store::istore)

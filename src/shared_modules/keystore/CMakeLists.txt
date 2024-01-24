cmake_minimum_required(VERSION 3.12.4)

project(keystore)

# enable_testing()

file(GLOB KEYSTORE_SRC
    "src/*.cpp"
    )

include_directories("../include")

add_library(keystore STATIC
    ${KEYSTORE_SRC}
    )

target_link_libraries(keystore rocksdb)

cmake_minimum_required(VERSION 3.12.4)
project(cert-creator)
set(OPENSSL_DIR "../../src/external/openssl/")

include_directories(${OPENSSL_DIR}include)

link_directories(${OPENSSL_DIR})

add_executable(cert-creator cert-creator.cpp)

target_link_libraries(cert-creator ssl)
target_link_libraries(cert-creator crypto)
target_link_libraries(cert-creator pthread)
target_link_libraries(cert-creator dl)

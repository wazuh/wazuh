cmake_minimum_required(VERSION 3.12.4)
project(cert_creation_tool)
set(OPENSSL_DIR "../../src/external/openssl/")

include_directories(${OPENSSL_DIR}include)

link_directories(${OPENSSL_DIR})

add_executable(cert-creator cert_creation_tool.cpp)

target_link_libraries(cert_creation_tool ssl)
target_link_libraries(cert_creation_tool crypto)
target_link_libraries(cert_creation_tool pthread)
target_link_libraries(cert_creation_tool dl)

cmake_minimum_required(VERSION 3.12.4)

project(https_client_tests)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
include_directories(${SRC_FOLDER}/external/googletest/googlemock/include/)

link_directories(${SRC_FOLDER}/external/googletest/lib/)

# runValgrind discovers module test binaries in build/bin by the
# "<module basename>*_test" naming; keep both properties intact.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(UNIT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/unit)

file(GLOB UNIT_SRC_FILES ${UNIT_SRC_DIR}/*.cpp)

add_executable(https_client_unit_test ${UNIT_SRC_FILES})

target_link_libraries(
  https_client_unit_test
  debug gtestd
  debug gmockd
  optimized gtest
  optimized gmock
  https_client
  ext_zstd
  # jwtSigner_test.cpp / enrollSigner_test.cpp check the minted bearers with the
  # shared verifiers (shared_modules/utils/jwt/, header-only over jwt-cpp +
  # rapidjson + OpenSSL). ext_jwt_cpp brings the static libcrypto.a (and, on
  # winagent, its crypt32/ws2_32 system deps): unlike libhttps_client.dll this
  # .exe does not link wazuhext, so OpenSSL resolves from the archive here.
  ext_jwt_cpp
  ext_rapidjson
  pthread)

target_include_directories(
  https_client_unit_test
  PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
          ${CMAKE_CURRENT_LIST_DIR}/../src
          ${UNIT_SRC_DIR}/mocks
          ${SRC_FOLDER}
          ${SRC_FOLDER}/shared_modules/utils
          ${SRC_FOLDER}/shared_modules/common
          ${SRC_FOLDER}/external/cJSON)

if(HTTPS_CLIENT_TSAN)
  target_compile_options(https_client_unit_test PRIVATE -fsanitize=thread -g)
  target_link_options(https_client_unit_test PRIVATE -fsanitize=thread)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  add_custom_command(
    TARGET https_client_unit_test
    POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_BINARY_DIR}/bin/libhttps_client.dll"
            "$<TARGET_FILE_DIR:https_client_unit_test>/libhttps_client.dll"
    COMMENT "Copying libhttps_client.dll next to the test executable")
endif()

add_test(NAME https_client_unit_test COMMAND https_client_unit_test)
set_tests_properties(https_client_unit_test PROPERTIES LABELS "https_client")

# Component test: real curl path vs a fork-based plaintext fake manager.
# fork() + a listening server make it Unix-only; excluded on winagent.
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
  file(GLOB COMPONENT_SRC_FILES ${CMAKE_CURRENT_LIST_DIR}/component/*.cpp)
  add_executable(https_client_component_test ${COMPONENT_SRC_FILES})
  # cpp-httplib SSLServer/SSLClient (the TLS fake manager) needs the OpenSSL
  # support macro and the vendored OpenSSL symbols linked directly (wazuhext
  # does not re-export them).
  # CPPHTTPLIB_ZSTD_SUPPORT: cpp-httplib >= 0.20 answers 415 to any
  # `Content-Encoding: zstd` request it cannot decode, so with the manager
  # tree's 0.25.0 the fake manager decodes compressed /stateful sessions the
  # way the real manager does (ext_zstd is linked below anyway). Agent builds
  # (Linux TARGET=agent, macOS) do not ship cpp-httplib in EXTERNAL_RES: the
  # http-request CMake downloads 0.10.9 (its EXTERNAL_DEPS_VERSION=19 default),
  # which ignores this macro and passes the frame through -- fakeManager.hpp
  # inflates it itself in that case, so the tests hold under both versions.
  target_compile_definitions(https_client_component_test PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT
                                                                 CPPHTTPLIB_ZSTD_SUPPORT)
  target_link_libraries(
    https_client_component_test
    debug gtestd
    debug gmockd
    optimized gtest
    optimized gmock
    https_client
    ext_zstd
    # The fake manager authenticates requests with the manager's own shared verifier
    # (shared_modules/utils/jwt/: jwt-cpp + rapidjson, both header-only).
    ext_jwt_cpp
    ext_rapidjson
    ${SRC_FOLDER}/external/openssl/libssl.a
    ${SRC_FOLDER}/external/openssl/libcrypto.a
    pthread)
  target_include_directories(
    https_client_component_test
    PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../include
            ${CMAKE_CURRENT_LIST_DIR}/../src
            ${SRC_FOLDER}
            ${SRC_FOLDER}/shared_modules/utils
            ${SRC_FOLDER}/shared_modules/common
            ${SRC_FOLDER}/external/cJSON
            ${SRC_FOLDER}/external/cpp-httplib
            ${SRC_FOLDER}/external/openssl/include
            ${SRC_FOLDER}/external/curl/include)
  add_test(NAME https_client_component_test COMMAND https_client_component_test)
  set_tests_properties(https_client_component_test PROPERTIES LABELS "https_client")
endif()

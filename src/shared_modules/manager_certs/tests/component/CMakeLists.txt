cmake_minimum_required(VERSION 3.12.4)

project(manager_certs_test_master CXX)

# The component test's own HTTPS master: a real cpp-httplib SSLServer (tests/testHttpsMaster.hpp),
# as a program the shell script starts and kills. It links NOTHING of the module under test -- it is
# the other side of the wire -- only cpp-httplib and the vendored OpenSSL its TLS needs, the same
# pair the https_client component test links for its own fake manager
# (src/client-agent/https_client/tests/CMakeLists.txt:80-95).
add_executable(${PROJECT_NAME} httpsMasterMain.cpp)
target_compile_definitions(${PROJECT_NAME} PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
target_include_directories(${PROJECT_NAME}
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..
          ${SRC_FOLDER}
          ${SRC_FOLDER}/external/cpp-httplib
          ${SRC_FOLDER}/external/openssl/include)
target_link_libraries(${PROJECT_NAME} PRIVATE ssl crypto pthread)

# End-to-end `--from-master`: the compiled binary against that server, over a real handshake. The
# GTest suite covers every guard through the MasterTransport/CurlPort seams; what cannot be faked --
# an untrusted CA, a wrong identity, ambient trust, a streamed body at the 1 MiB cap, a truncated
# one, a 302 -- lives here (C39h, objection 13). Carries the module-wide `manager_certs` label, like
# the CLI test, so `ctest -L manager_certs` runs the whole module.
add_test(NAME manager_certs_from_master
         COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/manager_certs_from_master_test.sh
                 $<TARGET_FILE:wazuh-manager-certs> $<TARGET_FILE:${PROJECT_NAME}>)
set_tests_properties(manager_certs_from_master PROPERTIES LABELS manager_certs)

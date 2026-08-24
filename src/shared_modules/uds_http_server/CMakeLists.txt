cmake_minimum_required(VERSION 3.12.4)

project(uds_http_server)

# Standalone-build support, same pattern as the other shared_modules.
if(NOT DEFINED SRC_FOLDER)
  get_filename_component(SRC_FOLDER ${CMAKE_CURRENT_SOURCE_DIR}/../../ ABSOLUTE)
endif()

add_library(wazuh_uds_http_server STATIC src/asioUdsHttpServer.cpp src/requestParser.cpp)

# Minimum 17 (the consumers include a strict-C++17 module: remoted_module); compiles unchanged
# under the tree-wide 20. The PUBLIC compile-feature is a FLOOR for consumers -- their own TUs
# keep their own standard -- while the archive's own TUs are PINNED to 17 below, so the promise
# is enforced on every build rather than trusted to review.
target_compile_features(wazuh_uds_http_server PUBLIC cxx_std_17)
set_target_properties(wazuh_uds_http_server PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)

# Static lib archived into shared libs (inventory_sync_server, vulnerability_scanner,
# remoted_module). NEVER make this SHARED: Log::GLOBAL_LOG_FUNCTION has hidden per-DSO
# visibility (see loggerHelper.h), so the archive must resolve it inside each consumer .so for
# every copy to log through its own module's sink.
set_target_properties(wazuh_uds_http_server PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Nothing in this archive is an export: every consumer embeds its own private copy, so any
# dynamic symbol that escapes a consumer .so is a defect waiting to happen -- measured in the
# wild before this was enforced, libinventory_sync_server.so ended up binding llhttp_execute
# from libvulnerability_scanner.so at runtime because VD exported it first and the linker never
# pulled inventory's own llhttp members. Two layers, because each covers what the other cannot:
#  - hidden visibility on the archive's OWN TUs kills its strong function/vtable exports, its
#    internal lambdas and its GNU-unique statics (which would otherwise be process-wide across
#    DSOs and pin dlclose);
#  - --exclude-libs, propagated to every embedder's link via INTERFACE, localizes whatever
#    still arrives from the archives -- crucially including llhttp, which may be a PRECOMPILED
#    imported archive (external/CMakeLists.txt) that no compile flag of ours can reach.
# Deliberately NOT hidden: the vague-linkage (weak) instantiations consumer TUs create from
# these headers. Hiding those (a header-wide visibility pragma) clamps every module function
# whose SIGNATURE mentions a lib type -- including sanctioned cross-boundary calls like
# content_manager::dispatchOnDemand and the module APIs the unit-test binaries link against --
# and identical weak template code collapsing across DSOs is ABI-normal C++, not a leak.
# LogThrottle marks itself hidden in its own header (its inline statics would export as
# GNU-unique from every consumer otherwise).
target_compile_options(wazuh_uds_http_server PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
target_link_options(wazuh_uds_http_server INTERFACE "LINKER:--exclude-libs,libwazuh_uds_http_server.a"
                    "LINKER:--exclude-libs,libllhttp.a")

target_include_directories(
  wazuh_uds_http_server
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${SRC_FOLDER}/shared_modules/utils # loggerHelper.h, proc.hpp
)

# Transport stays PRIVATE and confined behind the PImpl: no public header names asio or llhttp,
# which is what keeps makeUdsHttpServer() a one-line transport swap point.
target_link_libraries(wazuh_uds_http_server PRIVATE ext_asio ext_llhttp)

# Explicit rather than relying on asio's Boost auto-detection: nothing in this tree provides
# Boost, so leaving it to be inferred just makes the build depend on what happens to be installed.
target_compile_definitions(wazuh_uds_http_server PRIVATE ASIO_STANDALONE)

if(UNIT_TEST)
  set(BENCHMARK_TEST OFF)
  enable_testing()
  add_subdirectory(test)
endif()

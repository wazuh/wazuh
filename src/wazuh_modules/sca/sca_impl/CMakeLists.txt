cmake_minimum_required(VERSION 3.22)

project(SCAImpl)

# compile with C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# find_package(pcre2 CONFIG REQUIRED)
# find_package(yaml CONFIG REQUIRED)
get_filename_component(SRC_FOLDER ${CMAKE_SOURCE_DIR}/../../ ABSOLUTE)
message(STATUS "SRC_FOLDER: ${SRC_FOLDER}")
link_directories(${SRC_FOLDER})
link_directories(${SRC_FOLDER}/external/cJSON/)
link_directories(${SRC_FOLDER}/external/nlohmann/)
link_directories(${SRC_FOLDER}/external/libpcre2/)
link_directories(${SRC_FOLDER}/external/nlohmann/)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build)
link_directories(${SRC_FOLDER}/shared_modules/file_helper/build/lib)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build)
link_directories(${SRC_FOLDER}/shared_modules/dbsync/build/lib)
include_directories(${SRC_FOLDER}/external/cJSON/)
include_directories(${SRC_FOLDER}/external/libpcre2/include)
include_directories(${SRC_FOLDER}/external/nlohmann/)
include_directories(${SRC_FOLDER}/external/libyaml/include)
include_directories(${SRC_FOLDER}/shared_modules/common/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/filesystem/include/)
include_directories(${SRC_FOLDER}/shared_modules/file_helper/file_io/include/)
include_directories(${SRC_FOLDER}/shared_modules/dbsync/include/)
include_directories(${SRC_FOLDER}/shared_modules/utils/)
include_directories(${SRC_FOLDER}/data_provider/include/)

add_library(
    SCAImpl
    src/sca_impl.cpp
    src/yaml_document.cpp
    src/yaml_node.cpp
    src/sca_policy.cpp
    src/sca_policy_check.cpp
    src/sca_policy_loader.cpp
    src/sca_policy_parser.cpp
    src/sca_event_handler.cpp
    src/sca_utils.cpp
    src/check_condition_evaluator.cpp
    $<$<PLATFORM_ID:Windows>:src/sca_policy_check_win.cpp>
    ${SRC_FOLDER}/${RESOURCE_OBJ})

target_include_directories(SCAImpl PUBLIC include PRIVATE src)

target_compile_definitions(SCAImpl PRIVATE PCRE2_CODE_UNIT_WIDTH=8)

target_link_libraries(
    SCAImpl
    PUBLIC FilesystemWrapper # theres another wrapper in 4.x
           FileIO # readLineByLine and getFileContent are in 4.x
           dbsync # used extensively, available in 4.x, but no interface
           sysinfo # available in 4.x, uses processes method
           # nlohmann_json::nlohmann_json
    PRIVATE yaml
            # PCRE2::8BIT
            hash_helper # uses Utils::HashData class available in 4.x hashHelper.h
            string_helper # uses Utils::trim and Utils::asciiToHex (available in 4.x stringHelper.h)
            time_helper # uses Utils::getCurrentISO8601 available in 4.x timeHelper.h
            $<$<PLATFORM_ID:Windows>:registry_helper>) # uses Utils::Registry class (available) and Utils::KeyExists
                                                       # (not available)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

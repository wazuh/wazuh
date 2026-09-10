cmake_minimum_required(VERSION 3.10)
project(bounded_queue_test)

set(CMAKE_CXX_STANDARD 17)

include_directories(${SRC_FOLDER}/external/googletest/googletest/include/)
link_directories(${SRC_FOLDER}/external/googletest/lib/)

add_executable(bounded_queue_test bounded_queue_test.cpp)

target_link_libraries(bounded_queue_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

add_executable(btf_signature_test btf_signature_test.cpp ../../src/btf_signature.cpp)

target_include_directories(btf_signature_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../include)

target_link_libraries(btf_signature_test
    debug gtestd
    debug gtest_maind
    optimized gtest
    optimized gtest_main
    pthread
)

if(FSANITIZE)
    foreach(unit_test bounded_queue_test btf_signature_test)
        target_link_libraries(${unit_test}
            -fsanitize=address
            -fsanitize=undefined
        )
    endforeach(unit_test)
endif(FSANITIZE)

add_test(NAME bounded_queue_test
         COMMAND bounded_queue_test)

add_test(NAME btf_signature_test
         COMMAND btf_signature_test)

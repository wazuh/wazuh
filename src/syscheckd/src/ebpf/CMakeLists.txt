cmake_minimum_required(VERSION 3.10)

# Set the project name
project(fimebpf)

# Set the path to clang (update if necessary)
set(CLANG_PATH "/usr/bin/clang")

# Specify the directories for user-space includes (such as stdlib, stddef, etc.)
include_directories(
  ${CMAKE_SOURCE_DIR}/src/ebpf/include        # Your local includes
  /usr/include                                # Standard C library headers
)

# Specify the source files for the BPF program
set(BPF_SOURCES
  ${CMAKE_SOURCE_DIR}/src/ebpf/src/modern.bpf.c
)

# Compile the BPF program using clang
add_custom_target(bpf_obj ALL
  COMMAND ${CLANG_PATH} -target bpf -g -O2 -D__TARGET_ARCH_x86 -I${KERNEL_SRC_PATH}/include -I${KERNEL_SRC_PATH}/include/linux -I${CMAKE_SOURCE_DIR}/include -c ${BPF_SOURCES} -o ${CMAKE_BINARY_DIR}/modern.bpf.o
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# Create the executable for the loader
add_library(fimebpf SHARED ${CMAKE_SOURCE_DIR}/src/ebpf/src/ebpf_whodata.cpp)

# Link the loader executable with libbpf
target_link_libraries(fimebpf bpf)

# Set additional compile flags for the loader (if needed)
target_compile_options(fimebpf PRIVATE -Wall -Wextra)

# Add dependencies to ensure that the BPF object is compiled first
add_dependencies(fimebpf bpf_obj)
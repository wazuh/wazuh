# the name of the target operating system
SET(CMAKE_SYSTEM_NAME Windows)

# which compilers to use for C and C++
set(COMPILER_PREFIX "i686-w64-mingw32")
set(CMAKE_C_COMPILER ${COMPILER_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${COMPILER_PREFIX}-g++)
set(CMAKE_RC_COMPILER ${COMPILER_PREFIX}-windres)
set(CMAKE_C_LINK_EXECUTABLE "${CMAKE_C_COMPILER} <FLAGS> <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS>  -o <TARGET> <LINK_LIBRARIES>")
set(CMAKE_AR ${COMPILER_PREFIX}-ar)
set(CMAKE_RANLIB ${COMPILER_PREFIX}-ranlib)

find_program(WINE "wine")
IF(NOT WINE)
    message(WARNING "Wine needs to be installed to execute tests")
    message(WARNING "Install instruction for centos7 https://www.systutorials.com/239913/install-32-bit-wine-1-8-centos-7/")
ENDIF()
set(CMAKE_CROSSCOMPILING_EMULATOR wine)

# adjust the default behaviour of the FIND_XXX() commands:
# search headers and libraries in the target environment, search
# programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
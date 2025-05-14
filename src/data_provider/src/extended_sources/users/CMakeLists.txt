cmake_minimum_required(VERSION 3.10)

# TODO: find the propper var to use as TARGET
set(CMAKE_SYSTEM_NAME Windows)
if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_SYSTEM_PROCESSOR x86_64)
  set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
  set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
  set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
endif()

project(logged_in_users)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # TODO: should delete?
  set(MINGW_LIB_DIR "/usr/lib/gcc/x86_64-w64-mingw32/13-posix")
  set(MINGW_INCLUDE_DIR "/usr/x86_64-w64-mingw32/include")

  include_directories(include)
  include_directories(${CMAKE_SOURCE_DIR}/../../../../external/nlohmann/)
  include_directories(${CMAKE_SOURCE_DIR}/../../../../shared_modules/utils)
  include_directories(${MINGW_INCLUDE_DIR})

  # When using -D_WIN32_WINNT=0x600 the win32 api version wont build loggedInUser
  add_definitions(-DWIN32=1
                  -D_WIN32_WINNT=0x0601  # Windows 7 or later
                  -DWINVER=0x0601        # Windows 7 or later
                  -DWIN_EXPORT
                  -DUNICODE
                  -D_UNICODE)

  set(CMAKE_FIND_ROOT_PATH ${MINGW_LIB_DIR} /usr/x86_64-w64-mingw32)

  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static -static-libgcc -static-libstdc++")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static -static-libgcc")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -mwindows")

endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(SRC_FILES src/logged_in_users_win.cpp)
elseif(UNIX)
  set(SRC_FILES src/logged_in_users_unix.cpp)
else()
  message(FATAL_ERROR "Unsupported platform")
endif()

add_library(logged_in_users STATIC ${SRC_FILES})

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(logged_in_users PRIVATE
      psapi
      iphlpapi
      ws2_32
      wbemuuid
      advapi32
      kernel32
      user32
      gdi32
      winspool
      shell32
      uuid
      ole32
      oleaut32
      wtsapi32
  )
endif()

if(UNIT_TEST)
  add_subdirectory(tests)
endif()

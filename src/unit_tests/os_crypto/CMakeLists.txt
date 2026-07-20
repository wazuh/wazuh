# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

if(${TARGET} STREQUAL "manager")
    add_subdirectory(aes)
    add_subdirectory(hmac)
    add_subdirectory(shared)
    add_subdirectory(sha1)
    add_subdirectory(blowfish)
    add_subdirectory(md5)
    add_subdirectory(md5_sha1_sha256)
    add_subdirectory(sha256)
    add_subdirectory(sha512)
elseif(${TARGET} STREQUAL "agent" OR ${TARGET} STREQUAL "winagent")
    # All os_crypto sources are linked into the agent/winagent binaries
    # (shared/CMakeLists.txt:94). Pure-math subdirs (aes, sha*, md5*, hmac,
    # blowfish, signature) have no CLIENT/manager or POSIX/Win32 divergence,
    # so their tests are safe to run on both Linux agent and winagent.
    # `shared/` is excluded because msgs.c has #ifdef CLIENT branches that
    # change behavior vs the manager-only flow the tests were written against.
    if(${TARGET} STREQUAL "winagent")
        # TEST_DEPS (DEPENDENCIES_O + libwazuh_test) pulls in objects whose
        # `#ifdef WIN32` paths reference syscheckd symbols (syscom_dispatch,
        # Start_win32_Syscheck, is_fim_shutdown). The os_crypto tests don't
        # exercise those paths, but the references force the linker to resolve
        # them. Use the existing __wrap_* helpers in
        # src/unit_tests/wrappers/wazuh/syscheckd/ via link_libraries() so the
        # flags propagate to every target defined by the subdirs added below.
        link_libraries(
            -Wl,--wrap=syscom_dispatch
            -Wl,--wrap=Start_win32_Syscheck
            -Wl,--wrap=is_fim_shutdown)
    endif()
    add_subdirectory(aes)
    add_subdirectory(hmac)
    add_subdirectory(sha1)
    add_subdirectory(blowfish)
    add_subdirectory(md5)
    add_subdirectory(md5_sha1_sha256)
    add_subdirectory(sha256)
    add_subdirectory(sha512)
endif()

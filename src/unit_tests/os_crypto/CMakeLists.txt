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
elseif(${TARGET} STREQUAL "agent")
    # All os_crypto sources are linked into the agent binary (shared/CMakeLists.txt:94).
    # Pure-math subdirs (aes, sha*, md5*, hmac, blowfish, signature) have no CLIENT/manager
    # divergence, so their tests are safe to run on agent.
    # `shared/` is excluded because msgs.c has #ifdef CLIENT branches that change behavior
    # vs the manager-only flow the tests were written against.
    add_subdirectory(aes)
    add_subdirectory(hmac)
    add_subdirectory(sha1)
    add_subdirectory(blowfish)
    add_subdirectory(md5)
    add_subdirectory(md5_sha1_sha256)
    add_subdirectory(sha256)
    add_subdirectory(sha512)
endif()

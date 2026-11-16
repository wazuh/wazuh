# Copyright (C) Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

include_directories(${SRC_FOLDER}/shared/os_crypto/signature)

add_executable(test_signature test_signature.c)
target_link_libraries(test_signature ${TEST_DEPS}
                      "-Wl,--wrap,EVP_PKEY_verify -Wl,--wrap,EVP_DigestUpdate -Wl,--wrap,fstatvfs -Wl,--wrap,_merror")
add_test(NAME test_signature COMMAND test_signature)
# Keeps a blocking read from stalling the run.
set_tests_properties(test_signature PROPERTIES TIMEOUT 60)

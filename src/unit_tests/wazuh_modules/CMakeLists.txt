# Copyright (C) 2015-2020, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

add_subdirectory(aws)
add_subdirectory(azure)
add_subdirectory(ciscat)
add_subdirectory(command)
add_subdirectory(docker)
add_subdirectory(gcp)
add_subdirectory(oscap)
add_subdirectory(sca)
add_subdirectory(scheduling)
add_subdirectory(vulnerability_detector)

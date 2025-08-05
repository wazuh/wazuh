# Copyright (C) 2015, Wazuh Inc.
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

cmake_minimum_required(VERSION 3.10)

if(${TARGET} STREQUAL "server")
  add_subdirectory(aws)
  add_subdirectory(azure)
  add_subdirectory(command)
  add_subdirectory(database)
  add_subdirectory(docker)
  add_subdirectory(gcp)
  add_subdirectory(sca)
  add_subdirectory(scheduling)
  add_subdirectory(vulnerability_detection)
  add_subdirectory(task_manager)
  add_subdirectory(agent_upgrade)
  add_subdirectory(wmodules)
endif()

if(NOT ${TARGET} STREQUAL "winagent")
  add_subdirectory(control)
endif()

add_subdirectory(github)
add_subdirectory(office365)
add_subdirectory(ms_graph)
add_subdirectory(osquery)
add_subdirectory(exec)

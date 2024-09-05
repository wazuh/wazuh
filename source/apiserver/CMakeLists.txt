# Copyright (C) 2024 Wazuh Inc.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
# 
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


set(API_SERVER_SOURCE_DIR ${ENGINE_SOURCE_DIR}/apiserver/src)
set(API_SERVER_INCLUDE_DIR ${ENGINE_SOURCE_DIR}/apiserver/include)

####################################################################################################
# Sources - Includes
####################################################################################################
add_library(apiserver STATIC
    ${API_SERVER_SOURCE_DIR}/apiServer.cpp
)

target_link_libraries(apiserver base httplib::httplib)

target_include_directories(apiserver
    PUBLIC
    ${API_SERVER_INCLUDE_DIR}
)

# Tests
if(ENGINE_BUILD_TEST)

set(TEST_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/test/src)
set(COMPONENT_SRC_DIR ${TEST_SRC_DIR}/component)

add_executable(apiserver_ctest
    ${COMPONENT_SRC_DIR}/apiServer_test.cpp
)

target_link_libraries(apiserver_ctest PRIVATE GTest::gtest_main apiserver)
gtest_discover_tests(apiserver_ctest)

endif()

/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <atomic>
#include <csignal>
#include <string>
#include <thread>
#include <vector>

#include "Catalog.hpp"
#include "builder.hpp"
#include "catalog/storageDriver/disk/DiskStorage.hpp"
#include "cliParser.hpp"
#include "engineServer.hpp"
#include "glog/logging.h"
#include "graph.hpp"
#include "json.hpp"
#include "protocolHandler.hpp"
#include "register.hpp"
#include "router.hpp"

using std::atomic;
using std::endl;
using std::exception;
using std::make_unique;
using std::string;
using std::thread;
using std::vector;

#define WAIT_DEQUEUE_TIMEOUT_USEC (1 * 1000000)

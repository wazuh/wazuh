// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing
permissions and limitations under the License.
*/

#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <csignal>
#include <vector>
#include <string>
#include <memory>
#include <thread>
#include <chrono>
#include <unordered_set>
#include <functional>

#include <libsinsp/sinsp.h>
#include <libscap/scap_engines.h>
#include "ebpf_whodata.h"
#include "shared.h"

// Using specific std namespace items instead of using namespace std;
using std::string;
using std::vector;
using std::unique_ptr;
using std::shared_ptr;

namespace {

// Format strings for event formatting
const string default_output   = "%evt.num %evt.time cat=%evt.category container=%container.id proc=%proc.name(%proc.pid.%thread.tid) %evt.dir %evt.type %evt.args";
const string process_output   = "%evt.num %evt.time cat=%evt.category container=%container.id proc=%proc.name(%proc.pid.%thread.tid) ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] %evt.dir %evt.type %evt.args";
const string net_output       = "%evt.num %evt.time cat=%evt.category container=%container.id proc=%proc.name(%proc.pid.%thread.tid) ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] %evt.dir %evt.type %evt.args %fd.name";
const string plugin_output    = "%evt.num %evt.time [%evt.pluginname] %evt.plugininfo";

// Pointers to event formatters
unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;
unique_ptr<sinsp_evt_formatter> plugin_evt_formatter = nullptr;

// Filter check list and filter factory pointers
unique_ptr<filter_check_list> filter_list;
shared_ptr<sinsp_filter_factory> filter_factory;

}

// =============================================
// Utility function to get event field as string
std::string get_field_as_string(sinsp_evt* evt, sinsp& inspector, std::string_view field_name) {
    if(evt == nullptr) {
        throw sinsp_exception("The event pointer is NULL");
    }

    unique_ptr<sinsp_filter_check> chk(
            filter_list->new_filter_check_from_fldname(field_name, &inspector, false));
    if(chk == nullptr) {
        throw sinsp_exception("The field " + std::string(field_name) + " is not a valid field.");
    }
    // Create a filter check based on the field name
    chk->parse_field_name(field_name, true, false);

    const char* result = chk->tostring(evt);
    return (result == nullptr ? "" : string(result));
}

// =====================================================
// Function to create a filter string for multiple paths
std::string buildFilterString() {
    // Build filter string: (evt.abspath contains "path1") or (evt.abspath contains "path2") or ...
    filter = "(evt.type in (open, openat, openat2, creat, unlink, rename, write)";
    return filter;
}

// ========================================================================
// Function to setup filter with multiple paths
bool setupFilter(sinsp& inspector) {
    // Initialize filter check list and factory
    filter_list = std::make_unique<filter_check_list>();
    filter_factory = std::make_shared<sinsp_filter_factory>(&inspector, *filter_list.get());

    // Build filter string for multiple paths
    string filter_string = buildFilterString();
    auto filterLog { std::string("Setting filter: ") + filter_string };
    loggingFunction(LOG_DEBUG_VERBOSE, filterLog.c_str());

    try {
        sinsp_filter_compiler compiler(filter_factory, filter_string);
        unique_ptr<sinsp_filter> filter = compiler.compile();
        inspector.set_filter(std::move(filter), filter_string);
        return true;
    } catch (const sinsp_exception& e) {
        auto errorMessage { std::string("Unable to set filter: ") + e.what() };
        loggingFunction(LOG_ERROR, errorMessage.c_str());
        return false;
    }
}

// ========================================================================
// Function to initialize event formatters
void setupFormatters(sinsp& inspector) {
    default_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, default_output, *filter_list.get());
    process_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, process_output, *filter_list.get());
    net_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, net_output, *filter_list.get());
    plugin_evt_formatter = std::make_unique<sinsp_evt_formatter>(&inspector, plugin_output, *filter_list.get());
}

// ========================================================================
// Function to process a single event: format and send details to manager
void processEvent(sinsp& inspector, sinsp_evt* evt) {
    // Format event based on its category
    string formatted_output;
    if(evt->get_category() == EC_PROCESS) {
        process_formatter->tostring(evt, formatted_output);
    } else if(evt->get_category() == EC_NET || evt->get_category() == EC_IO_READ ||
              evt->get_category() == EC_IO_WRITE) {
        net_formatter->tostring(evt, formatted_output);
    } else if(evt->get_info()->category & EC_PLUGIN) {
        plugin_evt_formatter->tostring(evt, formatted_output);
    } else {
        default_formatter->tostring(evt, formatted_output);
    }

    // Send formatted event to manager
    sendFormattedEventToManager(formatted_output);

    // Create event details message
    try {
        string evt_time     = get_field_as_string(evt, inspector, "evt.time");
        string evt_type     = get_field_as_string(evt, inspector, "evt.type");
        string evt_category = get_field_as_string(evt, inspector, "evt.category");
        string proc_name    = get_field_as_string(evt, inspector, "proc.name");
        string inode        = get_field_as_string(evt, inspector, "fd.ino");
        string fs_name      = get_field_as_string(evt, inspector, "fs.path.name");
        string user_uid     = get_field_as_string(evt, inspector, "user.uid");
        string user_name    = get_field_as_string(evt, inspector, "user.name");
        string group_gid    = get_field_as_string(evt, inspector, "group.gid");
        string group_name   = get_field_as_string(evt, inspector, "group.name");
        string evt_args     = get_field_as_string(evt, inspector, "evt.args");

        string details = "[" + evt_time + "] " +
                         "user=" + user_name + "(" + user_uid + ") " +
                         "group=" + group_name + "(" + group_gid + ") " +
                         "type=" + evt_type + " " +
                         "cat=" + evt_category + " " +
                         "proc=" + proc_name + " " +
                         "fs.name=" + fs_name + " " +
                         "inode=" + inode + " " +
                         "args=" + evt_args;
        // Send event details to manager
        sendEventDetailsToManager(details);
    }
    catch(const sinsp_exception& e) {
        auto errorMessage { std::string("Error processing event details: ") + e.what() };
        loggingFunction(LOG_ERROR, errorMessage.c_str());
    }
}

// ========================================================================
// Function to run the event capture loop
void eventCaptureLoop(sinsp& inspector) {
    // Start capture and initialize formatters
    inspector.start_capture();
    loggingFunction(LOG_INFO, "Starting eBPF monitoring.");
    setupFormatters(inspector);

    while (true) {
        sinsp_evt* evt = nullptr;
        int res = inspector.next(&evt);

        if (res == SCAP_SUCCESS) {
            processEvent(inspector, evt);
        }
        else if (res == SCAP_EOF || res == SCAP_TIMEOUT || res == SCAP_FILTERED_EVENT) {
            continue;
        }
        else {
            auto errorMessage { std::string("Error capturing event: ") + inspector.getlasterr() };
            loggingFunction(LOG_ERROR, errorMessage.c_str());
        }
    }
}

// ========================================================================
// Function to initialize the BPF engine
bool initializeBPF(sinsp& inspector) {
    try {
        // ** Open the BPF engine **
        cout << "-- Trying to open BPF engine..." << endl;
        auto events_sc_codes = extract_filter_sc_codes(inspector);
        inspector.open_modern_bpf(16 * 4096, DEFAULT_CPU_FOR_EACH_BUFFER, false, events_sc_codes);
        cout << "BPF engine opened successfully!" << endl;
        return true;
    } catch (const sinsp_exception& e) {
        cerr << "Error opening BPF engine: " << e.what() << endl;
        return false;
    }
}

#ifdef __cplusplus
extern "C" {
#endif

// ========================================================================
// Function to initialize the eBPF engine
bool healthcheck_whodata_ebpf() {

    // Initialize BPF engine
    if (!initializeBPF(inspector)) {
        return false;
    } else {
        return true;
    }
}

// ========================================================================
// Whodata eBPF main thread
void ebpf_whodata() {
    // Convert C array to vector<string>
    vector<string> paths;
    for (int i = 0; i < num_paths; ++i) {
        paths.push_back(string(monitored_paths[i]));
    }

    sinsp inspector;

    // Initialize BPF engine
    if (!initializeBPF(inspector)) {
        return 1;
    }

    // Setup filter based on multiple paths
    if (inspector && setupFilter(inspector, paths)) {
        inspector.open_modern_bpf(DEFAULT_DRIVER_BUFFER_BYTES_DIM, DEFAULT_CPU_FOR_EACH_BUFFER, true, events_sc_codes);
        loggingFunction(LOG_INFO, "eBPF engine opened successfully");

        // Enter the event capture loop
        eventCaptureLoop(inspector);
    } else {
        auto errorMessage { std::string("Error initializing eBPF engine: ") + e.what() };
        loggingFunction(LOG_ERROR, errorMessage.c_str());
    }

	inspector.close();
}

#ifdef __cplusplus
}
#endif

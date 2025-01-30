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
#include <libsinsp/sinsp.h>
#include <libscap/scap_engines.h>
#include <unordered_set>
#include <functional>
#include <memory>
#include <thread>
#include <chrono>
#include "ebpf_whodata.h"

using namespace std;

static bool interrupted = false;
static string monitored_directory = "";
static std::unique_ptr<filter_check_list> filter_list;
static std::shared_ptr<sinsp_filter_factory> filter_factory;

#define EVENT_HEADER                                                \
	"%evt.num %evt.time cat=%evt.category container=%container.id " \
	"proc=%proc.name(%proc.pid.%thread.tid) "
#define EVENT_TRAILER "%evt.dir %evt.type %evt.args"

#define EVENT_DEFAULTS EVENT_HEADER EVENT_TRAILER
#define PROCESS_DEFAULTS \
	EVENT_HEADER "ppid=%proc.ppid exe=%proc.exe args=[%proc.cmdline] " EVENT_TRAILER

#define PLUGIN_DEFAULTS "%evt.num %evt.time [%evt.pluginname] %evt.plugininfo"

#define JSON_PROCESS_DEFAULTS                                                                   \
	"*%evt.num %evt.time %evt.category %container.id %proc.ppid %proc.pid %evt.type %proc.exe " \
	"%proc.cmdline %evt.args"

std::string default_output = EVENT_DEFAULTS;
std::string process_output = PROCESS_DEFAULTS;
std::string net_output = PROCESS_DEFAULTS " %fd.name";
std::string plugin_output = PLUGIN_DEFAULTS;

static std::unique_ptr<sinsp_evt_formatter> default_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> process_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> net_formatter = nullptr;
static std::unique_ptr<sinsp_evt_formatter> plugin_evt_formatter = nullptr;

// ** Signals handler to stop monitoring gracefully **
static void sigint_handler(int) {
    interrupted = true;
}

std::string get_field_as_string(sinsp_evt* evt,
                                sinsp& inspector,
                                std::string_view field_name) {
	if(evt == nullptr) {
		throw sinsp_exception("The event class is NULL");
	}

	std::unique_ptr<sinsp_filter_check> chk(
	        filter_list->new_filter_check_from_fldname(field_name, &inspector, false));
	if(chk == nullptr) {
		throw sinsp_exception("The field " + std::string(field_name) + " is not a valid field.");
	}
	// we created a filter check starting from the field name so if we arrive here we will find it
	// for sure
	chk->parse_field_name(field_name, true, false);

	const char* result = chk->tostring(evt);
	if(result == nullptr) {
		return "";
	}

	return result;
}

// ** Prints event details for debugging **
void formatted_dump(sinsp&, sinsp_evt* ev) {
	std::string output;
	if(ev->get_category() == EC_PROCESS) {
		process_formatter->tostring(ev, output);
	} else if(ev->get_category() == EC_NET || ev->get_category() == EC_IO_READ ||
	          ev->get_category() == EC_IO_WRITE) {
		net_formatter->tostring(ev, output);
	} else if(ev->get_info()->category & EC_PLUGIN) {
		plugin_evt_formatter->tostring(ev, output);
	} else {
		default_formatter->tostring(ev, output);
	}

	cout << output << std::endl;
}

static std::string determine_fim_type(sinsp_evt* evt, sinsp& inspector)
{
	// Retrieve some fields relevant to creation/writing
	std::string evt_type_str    = get_field_as_string(evt, inspector, "evt.type");

	// A simple lookup approach for "add", "modify", "delete"
	if(evt_type_str == "mkdir" ||
	   evt_type_str == "mkdirat" ||
	   evt_type_str == "creat" ||
	   evt_type_str == "openat")
	{
		return "add";
	}
	else if(evt_type_str == "unlink" ||
			evt_type_str == "unlinkat" ||
			evt_type_str == "rmdir")
	{
		return "delete";
	}
	else if(evt_type_str == "write" ||
			evt_type_str == "fchmodat")
	{
		return "modify";
	}

	return "unknown";
}

void print_event_details(sinsp_evt* evt, sinsp& inspector)
{
	if(!evt)
	{
		std::cerr << "Null event pointer!" << std::endl;
		return;
	}

	// Basic event info
	std::string evt_time       = get_field_as_string(evt, inspector, "evt.time");
	std::string evt_type       = get_field_as_string(evt, inspector, "evt.type");
	std::string evt_category   = get_field_as_string(evt, inspector, "evt.category");
	std::string proc_name      = get_field_as_string(evt, inspector, "proc.name");
	std::string inode          = get_field_as_string(evt, inspector, "fd.ino");

	// File path fields (Falco unifying fields)
	std::string fs_name        = get_field_as_string(evt, inspector, "fs.path.name");

	// User/group info
	std::string user_uid       = get_field_as_string(evt, inspector, "user.uid");
	std::string user_name      = get_field_as_string(evt, inspector, "user.name");
	std::string group_gid      = get_field_as_string(evt, inspector, "group.gid");
	std::string group_name     = get_field_as_string(evt, inspector, "group.name");

	// All syscall args (if you want to see them)
	std::string evt_args       = get_field_as_string(evt, inspector, "evt.args");

	// Our custom "fim_type_event"
	std::string fim_type_event       = determine_fim_type(evt, inspector);

	// Format them into one line (or many lines, JSON, etc. as you prefer)
	std::cout
		<< "[" << evt_time << "] "
		<< "fim_type_event=" << fim_type_event << " "
		<< "user=" << user_name << "(" << user_uid << ") "
		<< "group=" << group_name << "(" << group_gid << ") "
		<< "type=" << evt_type << " "
		<< "cat=" << evt_category << " "
		<< "proc=" << proc_name << " "
		<< "fs.name=" << fs_name << " "
		<< "inode=" << inode << " "
		<< "args=" << evt_args
		<< std::endl;
}

libsinsp::events::set<ppm_sc_code> extract_filter_sc_codes(sinsp& inspector) {
	auto ast = inspector.get_filter_ast();
	if(ast != nullptr) {
		return libsinsp::filter::ast::ppm_sc_codes(ast.get());
	}

	return {};
}

#ifdef __cplusplus
extern "C" {
#endif
int ebpf_whodata(char * monitored_path) {
    monitored_directory = monitored_path;

    cout << "Starting file monitoring for directory: " << monitored_directory << endl;

    sinsp inspector;

    // ** Try to open BPF engine **
    try {
        cout << "-- Trying to open BPF engine..." << endl;
        auto events_sc_codes = extract_filter_sc_codes(inspector);
        inspector.open_modern_bpf(16 * 4096, DEFAULT_CPU_FOR_EACH_BUFFER, false, events_sc_codes);
        cout << "BPF engine opened successfully!" << endl;
    } catch (const sinsp_exception& e) {
        cerr << "Error opening BPF engine: " << e.what() << endl;
        return 1;
    }

    // ** Set filter to capture only file-related events ** evt.type in (open, openat, openat2, creat, unlink, rename, write) and
    filter_list.reset(new sinsp_filter_check_list());
    filter_factory.reset(new sinsp_filter_factory(&inspector, *filter_list.get()));

    string filter_string = "(evt.abspath contains " + monitored_directory + ")";

    try {
        sinsp_filter_compiler compiler(filter_factory, filter_string);
        std::unique_ptr<sinsp_filter> s = compiler.compile();
        inspector.set_filter(std::move(s), filter_string);
    } catch (const sinsp_exception& e) {
        cerr << "Unable to set filter: " << e.what() << endl;
    }

	inspector.start_capture();
    cout << "Monitoring started... (Press Ctrl+C to stop)" << endl;

	default_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, default_output, *filter_list.get());
	process_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, process_output, *filter_list.get());
	net_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, net_output, *filter_list.get());
	plugin_evt_formatter =
	        std::make_unique<sinsp_evt_formatter>(&inspector, plugin_output, *filter_list.get());


    // ** Capture events loop with more debug logs **
    while (!interrupted) {
        sinsp_evt* evt = nullptr;
        int res = inspector.next(&evt);

        if (res == SCAP_SUCCESS) {
            if (evt == nullptr) {
                cerr << "Unexpected: Event pointer is null despite SCAP_SUCCESS." << endl;
                continue;
            }

            formatted_dump(inspector, evt);
            print_event_details(evt, inspector);
        }
        else if (res == SCAP_EOF) {
            cout << "End of capture." << endl;
            break;
        }
        else if (res == SCAP_TIMEOUT) {
            this_thread::sleep_for(chrono::milliseconds(1000));  // Sleep to prevent CPU usage spike
        }
        else if (res == SCAP_FILTERED_EVENT) {
        }
        else {
            cerr << "Error capturing event: " << inspector.getlasterr() << endl;
        }
    }

    cout << "Monitoring stopped." << endl;
    return 0;
}
#ifdef __cplusplus
}
#endif

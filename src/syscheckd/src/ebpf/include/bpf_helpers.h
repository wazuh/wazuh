/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * FIM's own event types and worker-thread declarations. The libbpf
 * load/attach/ring-buffer dispatch table that used to live here moved to
 * the standalone eBPF Module engine (src/shared_modules/ebpf_provider/) as
 * part of the #37396 cutover — ebpf_whodata.cpp now consumes that engine
 * through rt_open()/rt_poll()/rt_close() (see ebpf_whodata.hpp) instead of
 * loading libbpf itself, so none of the bpf_object__*/ring_buffer__*
 * plumbing that used to be declared here is needed in this file anymore.
 */

#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

#include <stdint.h>
#include <bounded_queue.hpp>
#include <memory>
#include <string>

struct dynamic_file_event
{
    std::string filename;
    std::string cwd;
    std::string parent_cwd;
    std::string comm;
    std::string parent_comm;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint64_t inode;
    uint64_t dev;
};

// One raw file-activity event classified as container-relevant (its path
// matched a configured `tags="container"` directory prefix) by handle_event(),
// queued for the slower cgroup->container resolution + host-path resolution +
// persist path in container_live_fim.cpp, off the ring-buffer-draining thread.
struct container_file_event
{
    std::string filename;   // Kernel-reported path, in the writer's own mount-ns view.
    uint64_t    cgroup_id;
    uint32_t    mnt_ns;
    uint32_t    pid;         // PID that triggered the hook — first choice for /proc/<pid>/root resolution.
    uint64_t    inode;
    uint64_t    dev;
};

// Worker threads (ebpf_whodata.cpp) draining the two queues above. Declared
// here (rather than only in ebpf_whodata.cpp) so they have external linkage
// for direct use by ebpf_whodata()'s thread-spawning code.
void ebpf_pop_events(fim::BoundedQueue<std::unique_ptr<dynamic_file_event>>& kernel_queue);
void ebpf_pop_container_events(fim::BoundedQueue<std::unique_ptr<container_file_event>>& container_queue);

#endif // BPF_HELPERS_H

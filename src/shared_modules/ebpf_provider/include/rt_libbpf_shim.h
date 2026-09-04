/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Minimal libbpf type shadow for rt_engine.c.
 *
 * rt_engine.c resolves every libbpf entry point through dlopen()/dlsym() at
 * rt_open() time and never links -lbpf, but it still needs libbpf's *types* to
 * declare its dispatch table. Including <bpf/libbpf.h> for that would make the
 * userspace loader — which must build everywhere, since consumers link it
 * unconditionally — depend on a libbpf development package being installed on
 * the build host. This tree ships no such headers of its own: the deps tarball
 * provides libbpf.so/libbpf.a under external/libbpf-bootstrap/build/libbpf/ and
 * nothing else, and the ExternalProject that would fetch the rest is
 * short-circuited whenever a prebuilt modern.bpf.o is present
 * (src/external/CMakeLists.txt). So the include would resolve against whatever
 * /usr/include/bpf happens to hold, or fail.
 *
 * So the types are shadowed here instead — the same pattern, and for the same
 * reason, as src/syscheckd/src/ebpf/include/wrapper_bpf.h, which shadows the
 * skeleton types rather than including libbpf's own.
 *
 * Everything rt_engine.c touches is an opaque pointer, so forward declarations
 * are enough; nothing here needs to match libbpf's layout, only its names. The
 * one exception is ring_buffer_sample_fn, whose signature is part of the ABI of
 * ring_buffer__new() and must match libbpf's exactly.
 */

#ifndef RT_LIBBPF_SHIM_H
#define RT_LIBBPF_SHIM_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque libbpf handles — only ever held and passed back as pointers. */
struct bpf_object;
struct bpf_object_open_opts;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct ring_buffer_opts;

/* Must match libbpf's declaration: the ring buffer calls this per record. */
typedef int (*ring_buffer_sample_fn)(void* ctx, void* data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* RT_LIBBPF_SHIM_H */

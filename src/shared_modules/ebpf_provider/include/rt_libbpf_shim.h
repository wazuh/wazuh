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
 * nothing else. So the include would resolve against whatever
 * /usr/include/bpf happens to hold, or fail.
 *
 * So the types are shadowed here instead — the same pattern, and for the same
 * reason, as the retired src/syscheckd/src/ebpf/include/wrapper_bpf.h, which
 * shadowed skeleton types rather than including libbpf's own. This shim now
 * owns the engine's type shadows.
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
/* BTF, for reading `enum cgroup_subsys_id` out of the running kernel. Opaque
 * like the rest: the engine never dereferences it. The BTF *record* layouts it
 * does have to read are declared in rt_engine.c under its own names rather than
 * here, so that shadowing them can never collide with <linux/btf.h> in a
 * translation unit that includes both. */
struct btf;
struct bpf_object_open_opts;
struct bpf_program;
struct bpf_link;
struct ring_buffer;
struct ring_buffer_opts;

/* Must match libbpf's declaration: the ring buffer calls this per record. */
typedef int (*ring_buffer_sample_fn)(void* ctx, void* data, size_t size);

/* BPF_MAP_TYPE_RINGBUF from the kernel's enum bpf_map_type (UAPI, so fixed),
 * for libbpf_probe_bpf_map_type(). */
#define RT_BPF_MAP_TYPE_RINGBUF 27

#ifdef __cplusplus
}
#endif

#endif /* RT_LIBBPF_SHIM_H */

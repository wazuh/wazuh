/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BTF_SIGNATURE_H
#define BTF_SIGNATURE_H

#include <cstddef>
#include <cstdint>

namespace fimebpf
{

/**
 * @brief Position of the dentry argument in the running kernel's
 *        security_inode_setattr() function, as reported by kernel BTF.
 *
 * Mainline < 6.0 takes (struct dentry *, struct iattr *), so the dentry is
 * the first argument. Mainline >= 6.0 (and vendor kernels that backported
 * the idmapped-mounts rework, e.g. RHEL/Rocky Linux 9's 5.14) takes
 * (struct mnt_idmap *, struct dentry *, struct iattr *), so the dentry is
 * the second argument. A numeric kernel-version check cannot tell these
 * apart on vendor kernels; BTF can.
 */
enum setattr_arg_index
{
    SETATTR_ARG_UNKNOWN = 0, ///< BTF missing, truncated or unparseable.
    SETATTR_ARG1 = 1,        ///< (struct dentry *, ...) - mainline < 6.0.
    SETATTR_ARG2 = 2,        ///< (struct mnt_idmap *, struct dentry *, ...) - 6.0+ / backports.
};

/**
 * @brief Determine which argument of security_inode_setattr() is the dentry
 *        by parsing the raw BTF of the running kernel.
 *
 * Implements a minimal, dependency-free reader of the raw BTF format
 * (no libbpf involved): it locates the BTF_KIND_FUNC entry named
 * "security_inode_setattr", walks to its FUNC_PROTO, and checks the first
 * two parameters, resolving typedef/const/volatile/restrict/type-tag
 * wrappers.
 *
 * @param btf_path Path to the raw BTF file (usually /sys/kernel/btf/vmlinux).
 * @return SETATTR_ARG1 if the first parameter is a `struct dentry *`;
 *         SETATTR_ARG2 if the first parameter is something else (the
 *         backported idmap) and the second parameter is a `struct dentry *`;
 *         SETATTR_ARG_UNKNOWN if the file cannot be read or parsed, or the
 *         signature matches neither layout.
 */
setattr_arg_index probe_security_inode_setattr(const char* btf_path);

/**
 * @brief In-memory variant of probe_security_inode_setattr(), exposed for
 *        unit tests that craft synthetic BTF blobs.
 */
setattr_arg_index probe_security_inode_setattr_buffer(const std::uint8_t* data, std::size_t size);

} // namespace fimebpf

#endif // BTF_SIGNATURE_H

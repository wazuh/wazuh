/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "btf_signature.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <vector>

namespace fimebpf
{

namespace
{

/*
 * Raw BTF layout (include/uapi/linux/btf.h):
 *
 *   struct btf_header {
 *       __u16 magic;      // offset 0  (0xeb9f)
 *       __u8  version;    // offset 2
 *       __u8  flags;      // offset 3
 *       __u32 hdr_len;    // offset 4
 *       __u32 type_off;   // offset 8,  relative to the end of the header
 *       __u32 type_len;   // offset 12
 *       __u32 str_off;    // offset 16, relative to the end of the header
 *       __u32 str_len;    // offset 20
 *   };
 */
constexpr std::uint16_t BTF_MAGIC = 0xeb9f;
constexpr std::size_t BTF_HEADER_SIZE = 24;
constexpr std::size_t OFF_HDR_LEN = 4;
constexpr std::size_t OFF_TYPE_OFF = 8;
constexpr std::size_t OFF_TYPE_LEN = 12;
constexpr std::size_t OFF_STR_OFF = 16;
constexpr std::size_t OFF_STR_LEN = 20;

/* struct btf_type { __u32 name_off; __u32 info; __u32 size_or_type; } */
constexpr std::size_t BTF_TYPE_SIZE = 12;
/* struct btf_param { __u32 name_off; __u32 type; } */
constexpr std::size_t BTF_PARAM_SIZE = 8;

/* btf_type.info encodings we care about. */
constexpr std::uint32_t BTF_KIND_INT = 1;
constexpr std::uint32_t BTF_KIND_PTR = 2;
constexpr std::uint32_t BTF_KIND_ARRAY = 3;
constexpr std::uint32_t BTF_KIND_STRUCT = 4;
constexpr std::uint32_t BTF_KIND_UNION = 5;
constexpr std::uint32_t BTF_KIND_ENUM = 6;
constexpr std::uint32_t BTF_KIND_TYPEDEF = 8;
constexpr std::uint32_t BTF_KIND_VOLATILE = 9;
constexpr std::uint32_t BTF_KIND_CONST = 10;
constexpr std::uint32_t BTF_KIND_RESTRICT = 11;
constexpr std::uint32_t BTF_KIND_FUNC = 12;
constexpr std::uint32_t BTF_KIND_FUNC_PROTO = 13;
constexpr std::uint32_t BTF_KIND_VAR = 14;
constexpr std::uint32_t BTF_KIND_DATASEC = 15;
constexpr std::uint32_t BTF_KIND_DECL_TAG = 17;
constexpr std::uint32_t BTF_KIND_TYPE_TAG = 18;
constexpr std::uint32_t BTF_KIND_ENUM64 = 19;

constexpr std::uint32_t BTF_MAX_TYPE_HOPS = 32; /* guard against wrapper-type cycles */
constexpr std::size_t BTF_MAX_FILE_SIZE = (64u << 20); /* sanity cap: 64 MiB */

std::uint32_t read_u32(const std::uint8_t* p)
{
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v; /* raw BTF is stored in the endianness of the running kernel */
}

std::uint16_t read_u16(const std::uint8_t* p)
{
    std::uint16_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

std::uint32_t type_kind(std::uint32_t info)
{
    return (info >> 24) & 0x1f;
}

std::uint32_t type_vlen(std::uint32_t info)
{
    return info & 0xffff;
}

/* Payload bytes appended after struct btf_type, per kind. */
std::uint64_t btf_record_extra_size(std::uint32_t kind, std::uint32_t vlen)
{
    switch (kind)
    {
        case BTF_KIND_INT: return 4;                                       /* u32 encoding */
        case BTF_KIND_ARRAY: return 12;                                    /* struct btf_array */
        case BTF_KIND_STRUCT:
        case BTF_KIND_UNION: return static_cast<std::uint64_t>(vlen) * 12; /* struct btf_member */
        case BTF_KIND_ENUM: return static_cast<std::uint64_t>(vlen) * 8;   /* struct btf_enum */
        case BTF_KIND_VAR: return 4;                                       /* u32 linkage */
        case BTF_KIND_DATASEC: return static_cast<std::uint64_t>(vlen) * 12; /* btf_var_secinfo */
        case BTF_KIND_DECL_TAG: return 4;                                  /* u32 component_idx */
        case BTF_KIND_ENUM64: return static_cast<std::uint64_t>(vlen) * 12; /* struct btf_enum64 */
        case BTF_KIND_FUNC_PROTO: return static_cast<std::uint64_t>(vlen) * 8; /* struct btf_param */
        default: return 0; /* PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC,
                              FLOAT, TYPE_TAG carry no extra payload */
    }
}

/**
 * @brief Minimal read-only cursor over a raw BTF blob.
 *
 * Every accessor is bounds-checked; on any inconsistency the whole probe
 * degrades to SETATTR_ARG_UNKNOWN so the loader can fall back to its
 * version heuristic instead of guessing from a half-parsed file.
 */
class BtfView
{
public:
    BtfView(const std::uint8_t* data, std::size_t size)
        : m_data(data)
        , m_size(size)
    {
    }

    bool valid() const
    {
        return m_size >= BTF_HEADER_SIZE && read_u16(m_data) == BTF_MAGIC;
    }

    /* Absolute offset of the type section within the blob. */
    std::size_t types_offset() const
    {
        const std::uint32_t hdrLen = read_u32(m_data + OFF_HDR_LEN);
        const std::uint32_t typeOff = read_u32(m_data + OFF_TYPE_OFF);
        return static_cast<std::size_t>(hdrLen) + typeOff;
    }

    std::size_t types_size() const
    {
        return read_u32(m_data + OFF_TYPE_LEN);
    }

    /* Sequentially walks the types section recording the offset (relative
     * to the section start) of every type id (ids start at 1), so later
     * lookups can be random-access. Returns false when the section is
     * truncated or malformed. */
    bool index_types()
    {
        const std::size_t limit = types_size();

        /* The section must exist entirely inside the blob. */
        if (types_offset() > m_size || limit > m_size - types_offset())
        {
            return false;
        }

        std::size_t offset = 0;
        while (offset + BTF_TYPE_SIZE <= limit)
        {
            m_typeOffsets.push_back(offset);

            std::uint32_t info = 0;
            if (!info_at(offset, info))
            {
                return false;
            }
            const std::uint64_t extra = btf_record_extra_size(type_kind(info), type_vlen(info));
            offset += BTF_TYPE_SIZE + static_cast<std::size_t>(extra);
        }

        return offset == limit; /* trailing garbage means the blob is malformed */
    }

    /* Offset of the record for type id `id` (ids start at 1). */
    bool type_offset(std::uint32_t id, std::size_t& offset) const
    {
        if (id == 0 || id > m_typeOffsets.size())
        {
            return false;
        }
        offset = m_typeOffsets[id - 1];
        return true;
    }

    /* The three fields of struct btf_type, addressed by section offset. */
    bool name_off_at(std::size_t offset, std::uint32_t& nameOff) const
    {
        return read_field(offset, 0, nameOff);
    }

    bool info_at(std::size_t offset, std::uint32_t& value) const
    {
        return read_field(offset, 4, value);
    }

    bool size_or_type_at(std::size_t offset, std::uint32_t& value) const
    {
        return read_field(offset, 8, value);
    }

    /* Returns the NUL-terminated string at `offset` of the string section,
     * or nullptr when out of bounds or not terminated. */
    const char* string_at(std::uint32_t offset) const
    {
        const std::uint32_t hdrLen = read_u32(m_data + OFF_HDR_LEN);
        const std::uint32_t strOff = read_u32(m_data + OFF_STR_OFF);
        const std::uint32_t strLen = read_u32(m_data + OFF_STR_LEN);

        if (offset >= strLen)
        {
            return nullptr;
        }

        const std::size_t base = static_cast<std::size_t>(hdrLen) + strOff;
        const std::size_t start = base + offset;
        if (base > m_size || start >= m_size)
        {
            return nullptr;
        }

        const char* s = reinterpret_cast<const char*>(m_data + start);
        const std::size_t remaining = m_size - start;
        std::size_t len = 0;
        while (len < remaining && s[len] != '\0')
        {
            ++len;
        }
        if (len == remaining)
        {
            return nullptr; /* not NUL-terminated inside the blob */
        }
        return s;
    }

    /* Parameter `index` (0-based) of the FUNC_PROTO record at `offset`. */
    bool proto_param(std::size_t offset, std::uint32_t index, std::uint32_t& paramType) const
    {
        std::uint32_t info = 0;
        if (!info_at(offset, info) || type_kind(info) != BTF_KIND_FUNC_PROTO)
        {
            return false;
        }
        if (index >= type_vlen(info))
        {
            return false;
        }
        const std::size_t paramOff = offset + BTF_TYPE_SIZE + static_cast<std::size_t>(index) * BTF_PARAM_SIZE;
        if (paramOff + BTF_PARAM_SIZE > types_size())
        {
            return false;
        }
        /* struct btf_param { __u32 name_off; __u32 type; } */
        return read_field(paramOff, 4, paramType);
    }

private:
    bool read_field(std::size_t offset, std::size_t field, std::uint32_t& value) const
    {
        const std::size_t abs = offset + field;
        if (abs + sizeof(std::uint32_t) > types_size())
        {
            return false;
        }
        value = read_u32(m_data + types_offset() + abs);
        return true;
    }

    const std::uint8_t* m_data;
    std::size_t m_size;
    std::vector<std::size_t> m_typeOffsets;
};

/* Strips TYPEDEF / VOLATILE / CONST / RESTRICT / TYPE_TAG wrappers. */
std::uint32_t resolve_type(const BtfView& btf, std::uint32_t id)
{
    for (std::uint32_t hops = 0; id != 0 && hops < BTF_MAX_TYPE_HOPS; ++hops)
    {
        std::size_t offset = 0;
        if (!btf.type_offset(id, offset))
        {
            return 0;
        }
        std::uint32_t info = 0;
        if (!btf.info_at(offset, info))
        {
            return 0;
        }
        const std::uint32_t kind = type_kind(info);
        if (kind != BTF_KIND_TYPEDEF && kind != BTF_KIND_VOLATILE && kind != BTF_KIND_CONST &&
            kind != BTF_KIND_RESTRICT && kind != BTF_KIND_TYPE_TAG)
        {
            return id;
        }
        std::uint32_t inner = 0;
        if (!btf.size_or_type_at(offset, inner))
        {
            return 0;
        }
        id = inner;
    }
    return 0;
}

/* True when `id` is a `struct dentry *` (wrapper types allowed). */
bool is_dentry_pointer(const BtfView& btf, std::uint32_t id)
{
    const std::uint32_t ptr = resolve_type(btf, id);
    std::size_t ptrOffset = 0;
    if (ptr == 0 || !btf.type_offset(ptr, ptrOffset))
    {
        return false;
    }

    std::uint32_t info = 0;
    if (!btf.info_at(ptrOffset, info) || type_kind(info) != BTF_KIND_PTR)
    {
        return false;
    }

    std::uint32_t pointeeId = 0;
    if (!btf.size_or_type_at(ptrOffset, pointeeId))
    {
        return false;
    }

    const std::uint32_t pointee = resolve_type(btf, pointeeId);
    std::size_t pointeeOffset = 0;
    if (pointee == 0 || !btf.type_offset(pointee, pointeeOffset))
    {
        return false;
    }

    if (!btf.info_at(pointeeOffset, info) || type_kind(info) != BTF_KIND_STRUCT)
    {
        return false;
    }

    std::uint32_t nameOff = 0;
    if (!btf.name_off_at(pointeeOffset, nameOff))
    {
        return false;
    }
    const char* name = btf.string_at(nameOff);
    return name != nullptr && std::strcmp(name, "dentry") == 0;
}

} // namespace

setattr_arg_index probe_security_inode_setattr_buffer(const std::uint8_t* data, std::size_t size)
{
    if (data == nullptr)
    {
        return SETATTR_ARG_UNKNOWN;
    }

    BtfView btf(data, size);
    if (!btf.valid() || !btf.index_types())
    {
        return SETATTR_ARG_UNKNOWN;
    }

    /* Find the BTF_KIND_FUNC entry named security_inode_setattr; its
     * size_or_type field references the FUNC_PROTO describing its params. */
    std::size_t protoOffset = 0;
    bool found = false;
    for (std::size_t offset = 0; offset + BTF_TYPE_SIZE <= btf.types_size();)
    {
        std::uint32_t info = 0;
        if (!btf.info_at(offset, info))
        {
            break;
        }

        if (type_kind(info) == BTF_KIND_FUNC)
        {
            std::uint32_t nameOff = 0;
            if (btf.name_off_at(offset, nameOff))
            {
                const char* name = btf.string_at(nameOff);
                if (name != nullptr && std::strcmp(name, "security_inode_setattr") == 0)
                {
                    std::uint32_t protoId = 0;
                    if (!btf.size_or_type_at(offset, protoId) || !btf.type_offset(protoId, protoOffset))
                    {
                        return SETATTR_ARG_UNKNOWN;
                    }
                    found = true;
                    break;
                }
            }
        }

        offset += BTF_TYPE_SIZE + static_cast<std::size_t>(btf_record_extra_size(type_kind(info), type_vlen(info)));
    }

    if (!found)
    {
        return SETATTR_ARG_UNKNOWN;
    }

    std::uint32_t first = 0;
    if (!btf.proto_param(protoOffset, 0, first))
    {
        return SETATTR_ARG_UNKNOWN;
    }

    if (is_dentry_pointer(btf, first))
    {
        return SETATTR_ARG1;
    }

    std::uint32_t second = 0;
    if (btf.proto_param(protoOffset, 1, second) && is_dentry_pointer(btf, second))
    {
        return SETATTR_ARG2;
    }

    return SETATTR_ARG_UNKNOWN;
}

setattr_arg_index probe_security_inode_setattr(const char* btf_path)
{
    if (btf_path == nullptr)
    {
        return SETATTR_ARG_UNKNOWN;
    }

    std::ifstream file(btf_path, std::ios::binary | std::ios::ate);
    if (!file)
    {
        return SETATTR_ARG_UNKNOWN;
    }

    const std::streampos end = file.tellg();
    if (end < 0)
    {
        return SETATTR_ARG_UNKNOWN;
    }
    const auto size = static_cast<std::size_t>(end);
    if (size < BTF_HEADER_SIZE || size > BTF_MAX_FILE_SIZE)
    {
        return SETATTR_ARG_UNKNOWN;
    }

    std::vector<std::uint8_t> buffer(size);
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(size)))
    {
        return SETATTR_ARG_UNKNOWN;
    }

    return probe_security_inode_setattr_buffer(buffer.data(), buffer.size());
}

} // namespace fimebpf

/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "btf_signature.h"

namespace
{

/* Kind values as encoded in btf_type.info (kind field). */
constexpr std::uint32_t kKindInt = 1;
constexpr std::uint32_t kKindPtr = 2;
constexpr std::uint32_t kKindStruct = 4;
constexpr std::uint32_t kKindTypedef = 8;
constexpr std::uint32_t kKindFunc = 12;
constexpr std::uint32_t kKindFuncProto = 13;

/* Little helper to assemble a raw BTF blob:
 *
 *   header: magic 0xeb9f, version 1, hdr_len 24,
 *           type section and string section laid out back to back.
 *
 * Types are appended sequentially with ids starting at 1; strings are
 * deduplicated through a builder so name offsets stay consistent.
 */
class BtfBuilder
{
public:
    /* Appends struct btf_type {name_off, info, size_or_type} plus extra payload.
     * vlen must be given explicitly because its meaning depends on the kind
     * (e.g. FUNC_PROTO counts parameters, not u32 words). */
    std::uint32_t add_type(const char* name, std::uint32_t kind, std::uint32_t size_or_type,
                           const std::vector<std::uint32_t>& extra = {}, std::uint32_t vlen = 0)
    {
        const std::uint32_t id = ++m_nextId;

        const std::uint32_t nameOff = name ? add_string(name) : 0;
        append_u32(m_types, nameOff);
        append_u32(m_types, (kind << 24) | (vlen & 0xffff));
        append_u32(m_types, size_or_type);
        for (const std::uint32_t word : extra)
        {
            append_u32(m_types, word);
        }

        return id;
    }

    std::uint32_t add_string(const char* s)
    {
        auto it = m_strings.find(s);
        if (it != m_strings.end())
        {
            return it->second;
        }
        const std::uint32_t offset = static_cast<std::uint32_t>(m_str.size());
        m_str.insert(m_str.end(), s, s + std::strlen(s) + 1);
        m_strings[s] = offset;
        return offset;
    }

    std::vector<std::uint8_t> build() const
    {
        std::vector<std::uint8_t> out;

        append_u16(out, 0xeb9f);            // magic
        out.push_back(1);                   // version
        out.push_back(0);                   // flags
        append_u32(out, 24);                // hdr_len
        append_u32(out, 0);                 // type_off (right after header)
        append_u32(out, static_cast<std::uint32_t>(m_types.size())); // type_len
        append_u32(out, static_cast<std::uint32_t>(m_types.size())); // str_off (right after the type section)
        append_u32(out, static_cast<std::uint32_t>(m_str.size()));   // str_len

        out.insert(out.end(), m_types.begin(), m_types.end());
        out.insert(out.end(), m_str.begin(), m_str.end());
        return out;
    }

private:
    static void append_u16(std::vector<std::uint8_t>& out, std::uint16_t v)
    {
        out.push_back(static_cast<std::uint8_t>(v & 0xff));
        out.push_back(static_cast<std::uint8_t>(v >> 8));
    }

    static void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v)
    {
        append_u16(out, static_cast<std::uint16_t>(v & 0xffff));
        append_u16(out, static_cast<std::uint16_t>(v >> 16));
    }

    std::vector<std::uint8_t> m_types;
    std::vector<std::uint8_t> m_str;
    std::map<std::string, std::uint32_t> m_strings;
    std::uint32_t m_nextId = 0;
};

/* Builds: [0] int; [1] struct dentry; [2] struct mnt_idmap; [3] ptr->dentry;
 * [4] ptr->idmap; then FUNC_PROTO(params...) and FUNC. */
std::vector<std::uint8_t> build_setattr_btf(BtfBuilder& b, std::uint32_t param1, std::uint32_t param2)
{
    b.add_type(nullptr, kKindInt, 4, {0});                          // id 1: int
    const std::uint32_t dentry = b.add_type("dentry", kKindStruct, 0); // id 2
    const std::uint32_t idmap = b.add_type("mnt_idmap", kKindStruct, 0); // id 3
    const std::uint32_t ptrDentry = b.add_type(nullptr, kKindPtr, dentry);   // id 4
    const std::uint32_t ptrIdmap = b.add_type(nullptr, kKindPtr, idmap);     // id 5

    // FUNC_PROTO with 2 params: {name_off, type} pairs, 8 bytes each.
    const std::uint32_t protoId = b.add_type(
        nullptr,
        kKindFuncProto,
        0, /* return type: 0 = void */
        {b.add_string("idmap"), param1, b.add_string("dentry"), param2},
        /*vlen=*/2);

    b.add_type("security_inode_setattr", kKindFunc, protoId);

    (void)ptrDentry;
    (void)ptrIdmap;
    return b.build();
}

} // namespace

/* Mainline < 6.0: security_inode_setattr(struct dentry *, struct iattr *). */
TEST(BtfSignatureTest, DentryFirstArgument)
{
    BtfBuilder b;
    auto blob = build_setattr_btf(b, /*param1=*/4, /*param2=*/1);
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), blob.size()), fimebpf::SETATTR_ARG1);
}

/* Mainline >= 6.0 and vendor backports (Rocky 9's 5.14):
 * security_inode_setattr(struct mnt_idmap *, struct dentry *, struct iattr *). */
TEST(BtfSignatureTest, IdmapFirstDentrySecond)
{
    BtfBuilder b;
    auto blob = build_setattr_btf(b, /*param1=*/5, /*param2=*/4);
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), blob.size()), fimebpf::SETATTR_ARG2);
}

/* Typedef wrappers around the pointer or the struct must be resolved. */
TEST(BtfSignatureTest, TypedefedDentryPointer)
{
    BtfBuilder b;
    b.add_type(nullptr, kKindInt, 4, {0});                             // id 1
    const std::uint32_t dentry = b.add_type("dentry", kKindStruct, 0); // id 2
    b.add_type("mnt_idmap", kKindStruct, 0);                           // id 3
    const std::uint32_t ptrDentry = b.add_type(nullptr, kKindPtr, dentry); // id 4
    b.add_type(nullptr, kKindPtr, 3);                                  // id 5
    const std::uint32_t td = b.add_type("dentry_t", kKindTypedef, ptrDentry); // id 6

    const auto blob = build_setattr_btf(b, /*param1=*/5, /*param2=*/td);
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), blob.size()), fimebpf::SETATTR_ARG2);
}

/* The func must be found by name; a different func name must not match. */
TEST(BtfSignatureTest, FuncNotFoundByName)
{
    BtfBuilder b;
    b.add_type(nullptr, kKindInt, 4, {0});                             // id 1
    const std::uint32_t dentry = b.add_type("dentry", kKindStruct, 0); // id 2
    const std::uint32_t ptrDentry = b.add_type(nullptr, kKindPtr, dentry); // id 3

    const std::uint32_t protoId =
        b.add_type(nullptr, kKindFuncProto, 0, {b.add_string("dentry"), ptrDentry}, /*vlen=*/1);
    b.add_type("security_inode_getattr", kKindFunc, protoId);

    const auto blob = b.build();
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), blob.size()),
              fimebpf::SETATTR_ARG_UNKNOWN);
}

/* Missing the function entirely (e.g. CONFIG_DEBUG_INFO_BTF without the
 * security layer exported) must degrade to UNKNOWN. */
TEST(BtfSignatureTest, NoSetattrFunc)
{
    BtfBuilder b;
    b.add_type(nullptr, kKindInt, 4, {0});
    const auto blob = b.build();
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), blob.size()),
              fimebpf::SETATTR_ARG_UNKNOWN);
}

/* Truncated / garbage input must degrade to UNKNOWN, never crash. */
TEST(BtfSignatureTest, MalformedInputs)
{
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(nullptr, 0), fimebpf::SETATTR_ARG_UNKNOWN);

    std::vector<std::uint8_t> garbage(64, 0xab);
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(garbage.data(), garbage.size()),
              fimebpf::SETATTR_ARG_UNKNOWN);

    BtfBuilder b;
    auto blob = build_setattr_btf(b, 4, 1);
    for (std::size_t cut = 0; cut < blob.size(); cut += 7)
    {
        EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), cut),
                  fimebpf::SETATTR_ARG_UNKNOWN)
            << "truncated at " << cut;
    }
}

/* A struct named something other than "dentry" as the first parameter must
 * not be mistaken for the dentry layout. */
TEST(BtfSignatureTest, FirstParamOtherStruct)
{
    BtfBuilder b;
    b.add_type(nullptr, kKindInt, 4, {0});                          // id 1
    b.add_type("dentry", kKindStruct, 0);                           // id 2
    const std::uint32_t inode = b.add_type("inode", kKindStruct, 0); // id 3
    const std::uint32_t ptrInode = b.add_type(nullptr, kKindPtr, inode); // id 4
    b.add_type(nullptr, kKindPtr, 2);                               // id 5

    const auto blob = build_setattr_btf(b, /*param1=*/ptrInode, /*param2=*/5);
    EXPECT_EQ(fimebpf::probe_security_inode_setattr_buffer(blob.data(), blob.size()), fimebpf::SETATTR_ARG2);
}

TEST(BtfSignatureTest, FileNotFound)
{
    EXPECT_EQ(fimebpf::probe_security_inode_setattr("/nonexistent/btf/path"), fimebpf::SETATTR_ARG_UNKNOWN);
    EXPECT_EQ(fimebpf::probe_security_inode_setattr(nullptr), fimebpf::SETATTR_ARG_UNKNOWN);
}

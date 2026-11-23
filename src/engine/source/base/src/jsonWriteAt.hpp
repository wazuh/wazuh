// SPDX-License-Identifier: AGPL-3.0-or-later
#ifndef _BASE_JSON_WRITE_AT_HPP
#define _BASE_JSON_WRITE_AT_HPP

#include <cstddef>
#include <type_traits>

#include <base/json.hpp>

namespace json::internal
{

/// Result of a linear member lookup: the member, or null if the object has no member of that name.
struct LinearLookup
{
    json::Value::Member* member;
};

/// Same member lookup as rapidjson's GenericPointer: a linear scan, the first occurrence of a name wins.
inline LinearLookup findLinear(json::Value& object, const json::Pointer::Token& token)
{
    const auto found = object.FindMember(json::Value(rapidjson::StringRef(token.name, token.length)));
    return {found == object.MemberEnd() ? nullptr : &*found};
}

/**
 * @brief `Pointer::Set` from a node that leaves the document as it was when an allocation fails.
 *
 * rapidjson's `Create()` resets a scalar on the path with `SetObject()`/`SetArray()` and adds the missing levels one at
 * a time, before the allocations that can fail. Here the work runs in a fixed order:
 *  1. the part of the path that exists is only read (`find` may allocate, but never touches the document);
 *  2. the missing part is built apart, around the leaf;
 *  3. it is attached in one step (`AddMember`, `Reserve` and `PushBack` reallocate before they touch the node; a
 *     replaced node is overwritten by a `noexcept` move);
 *  4. the hooks run: `memberAdded(object, lookup)` after the member that attaches the missing part was added to an
 *     existing object (`lookup` is the failed lookup of its name in that object), `replacing(node)` right before an
 *     existing node is overwritten. Both are `noexcept`.
 * Same semantics as `Create()`: a name token turns a non-object into an object, an index token turns a scalar into an
 * array padded with nulls, `-` appends to an array.
 *
 * @param allocator Allocator of the document.
 * @param from Node the tokens are relative to.
 * @param tokens Tokens of the path.
 * @param count Number of tokens.
 * @param leaf Value to write, moved into the document. Null means "ensure": an existing target is not touched, a
 * missing one is created as null.
 * @param find Member lookup: `find(object, token)` returns a value whose `.member` is the member or null.
 * @param memberAdded Hook run after a member was added to an existing object.
 * @param replacing Hook run right before an existing node is overwritten.
 * @return The target node, already attached to the document.
 */
template<typename Find, typename MemberAdded, typename Replacing>
json::Value& writeAt(json::Value::AllocatorType& allocator,
                     json::Value& from,
                     const json::Pointer::Token* tokens,
                     size_t count,
                     json::Value* leaf,
                     Find&& find,
                     MemberAdded&& memberAdded,
                     Replacing&& replacing)
{
    using Token = json::Pointer::Token;
    const auto isName = [](const Token& t)
    {
        return t.index == rapidjson::kPointerInvalidIndex;
    };
    const auto isAppend = [](const Token& t)
    {
        return t.length == 1 && t.name[0] == '-';
    };

    // 1. Read the part of the path that exists
    std::invoke_result_t<Find&, json::Value&, const Token&> lookup {};
    json::Value* node = &from;
    size_t i = 0;
    for (; i < count; ++i)
    {
        const auto& t = tokens[i];
        if (node->IsArray())
        {
            if (isName(t) || t.index >= node->Size())
            {
                break;
            }
            node = &(*node)[t.index];
        }
        else if (node->IsObject())
        {
            lookup = find(*node, t);
            if (lookup.member == nullptr)
            {
                break;
            }
            node = &lookup.member->value;
        }
        else
        {
            break;
        }
    }

    if (i == count)
    {
        if (leaf != nullptr)
        {
            replacing(*node);
            *node = *leaf; // noexcept move
        }
        return *node;
    }

    // 2. Levels below the attach point, innermost first, around the leaf
    const auto wrap = [&](const Token& t, json::Value& inner)
    {
        json::Value level;
        if (isName(t))
        {
            level.SetObject();
            json::Value name(t.name, t.length, allocator);
            level.AddMember(name, inner, allocator);
        }
        else
        {
            level.SetArray();
            level.Reserve(t.index + 1, allocator);
            while (level.Size() < t.index)
            {
                level.PushBack(json::Value(), allocator);
            }
            level.PushBack(inner, allocator);
        }
        return level;
    };
    json::Value chain;
    if (leaf != nullptr)
    {
        chain = *leaf;
    }
    for (size_t j = count; j > i + 1; --j)
    {
        chain = wrap(tokens[j - 1], chain);
    }

    // 3. Attach in one step, then 4. run the hooks
    const auto& t = tokens[i];
    json::Value* attached = nullptr;
    size_t levels = count - i - 1; // levels of `chain` above the target
    if (node->IsObject())
    {
        json::Value name(t.name, t.length, allocator);
        node->AddMember(name, chain, allocator);
        memberAdded(*node, lookup);
        attached = &(node->MemberEnd() - 1)->value; // AddMember appends at the end
    }
    else if (node->IsArray() && isAppend(t))
    {
        node->PushBack(chain, allocator);
        attached = &(*node)[node->Size() - 1];
    }
    else if (node->IsArray() && !isName(t))
    {
        node->Reserve(t.index + 1, allocator);
        while (node->Size() < t.index)
        {
            node->PushBack(json::Value(), allocator); // within the reserved capacity: no allocation
        }
        node->PushBack(chain, allocator);
        attached = &(*node)[node->Size() - 1];
    }
    else
    {
        // A scalar, or an array addressed by a name: the node itself is replaced
        chain = wrap(t, chain);
        replacing(*node);
        *node = chain; // noexcept move
        attached = node;
        ++levels;
    }

    // The suffix moved into the document: walk down to the target again. Every level built above holds a single
    // member or ends at the element that leads to the target.
    for (; levels != 0; --levels)
    {
        attached = attached->IsObject() ? &attached->MemberBegin()->value : &(*attached)[attached->Size() - 1];
    }
    return *attached;
}

} // namespace json::internal

#endif // _BASE_JSON_WRITE_AT_HPP

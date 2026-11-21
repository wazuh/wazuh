// SPDX-License-Identifier: AGPL-3.0-or-later
#include <base/jsonPathWriter.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

#include <fmt/format.h>

#include "jsonNameCompare.hpp"
#include "jsonWriteAt.hpp"

namespace json
{

// The index is keyed by the address of each object's member array, and anchors are node addresses. That holds because
// the pool allocator of the engine documents never reuses memory while the document lives: Free is a no-op, and a
// reallocation either grows the block in place (same address, same object) or moves it to fresh memory. So an
// address that was retired (by an overwritten object or a moved member array) never names another object's member
// array later, and an entry left behind by it is never matched again. The assertions tie the writer to that pool:
// json::Allocator derives from it and redeclares none of Malloc, Realloc or Free (compared by address: Free is
// static, so a redeclaration with the same signature would have the same type), and the pool does not need Free.
static_assert(std::is_base_of_v<rapidjson::MemoryPoolAllocator<json::BaseAllocator>, json::Document::AllocatorType>,
              "PathWriter relies on the pool allocator of json::Document never reusing a retired address");
static_assert(std::is_same_v<json::Document::AllocatorType, json::Allocator>,
              "PathWriter relies on json::Document using json::Allocator");
static_assert(&json::Allocator::Malloc == &rapidjson::MemoryPoolAllocator<json::BaseAllocator>::Malloc,
              "json::Allocator must not redeclare Malloc: PathWriter relies on the pool never reusing an address");
static_assert(&json::Allocator::Realloc == &rapidjson::MemoryPoolAllocator<json::BaseAllocator>::Realloc,
              "json::Allocator must not redeclare Realloc: PathWriter relies on the pool never reusing an address");
static_assert(&json::Allocator::Free == &rapidjson::MemoryPoolAllocator<json::BaseAllocator>::Free,
              "json::Allocator must not redeclare Free: PathWriter relies on the pool never reusing an address");
static_assert(!json::Allocator::kNeedFree,
              "PathWriter relies on the pool allocator of json::Document never freeing a block while it lives");

namespace
{

using Member = json::Value::Member;
using Token = json::Pointer::Token;

using internal::compareNames;

std::string_view nameOf(const Member& member)
{
    return {member.name.GetString(), member.name.GetStringLength()};
}

// Same transformation as Json's asMemberTokens: every token is read as an object member name.
std::vector<Token> asMemberTokens(const json::Pointer& pointer)
{
    std::vector<Token> tokens(pointer.GetTokens(), pointer.GetTokens() + pointer.GetTokenCount());
    for (auto& token : tokens)
    {
        token.index = rapidjson::kPointerInvalidIndex;
    }
    return tokens;
}

const Token* tokensBegin(const json::Pointer& pointer)
{
    return pointer.GetTokens();
}

const Token* tokensEnd(const json::Pointer& pointer)
{
    return pointer.GetTokens() + pointer.GetTokenCount();
}

// The pointer of a relative path, built once: a single return of a prvalue is elided (json::Pointer has no move
// constructor, so returning a named pointer would copy it). The empty path never reads relPath.data(), and a path
// that does not start with '/' is not parsed: both give the empty pointer, and checkRelativePointer() tells them apart.
json::Pointer relativePointer(std::string_view relPath)
{
    return relPath.empty() || relPath[0] != '/' ? json::Pointer() : json::makePointer(relPath);
}

// A relative path is valid when it is empty or starts with '/' and is a valid JSON pointer (no URI fragment form)
void checkRelativePointer(const json::Pointer& pointer, std::string_view relPath)
{
    if (relPath.empty() || (relPath[0] == '/' && pointer.IsValid()))
    {
        return;
    }
    throw std::runtime_error(fmt::format("Invalid relative pointer path '{}'", relPath));
}

} // namespace

bool PathWriter::NameLess::operator()(Position lhs, Position rhs) const
{
    return compareNames(nameOf(entry->base[lhs]), nameOf(entry->base[rhs])) < 0;
}

bool PathWriter::NameLess::operator()(Position lhs, std::string_view rhs) const
{
    return compareNames(nameOf(entry->base[lhs]), rhs) < 0;
}

bool PathWriter::NameLess::operator()(std::string_view lhs, Position rhs) const
{
    return compareNames(lhs, nameOf(entry->base[rhs])) < 0;
}

PathWriter::PathWriter(Json& doc, size_t indexThreshold)
    : m_doc(doc)
    , m_indexThreshold(indexThreshold)
{
}

PathWriter::~PathWriter() = default;

PathWriter::Lookup PathWriter::findMember(Value& object, const Token& token) const
{
    const Position count = object.MemberCount();
    if (count <= m_indexThreshold)
    {
        // Same lookup as rapidjson's GenericPointer
        const auto found = object.FindMember(Value(rapidjson::GenericStringRef<char>(token.name, token.length)));
        return {found == object.MemberEnd() ? nullptr : &*found, nullptr};
    }

    Member* members = &*object.MemberBegin();
    IndexEntry* entry = nullptr;
    try
    {
        entry = &m_index.try_emplace(members, members).first->second;
        if (entry->indexed != count)
        {
            // New entry (or one that missed members): index every member in order, so the first occurrence of a name
            // wins
            entry->positions.clear();
            entry->indexed = 0;
            for (Position position = 0; position < count; ++position)
            {
                entry->positions.insert(position);
            }
            entry->indexed = count;
        }
    }
    catch (...)
    {
        // Only the document is read here: drop the entry so that none is left half built, and let the write fail
        m_index.erase(members);
        throw;
    }

    const auto found = entry->positions.find(std::string_view(token.name, token.length));
    return {found == entry->positions.end() ? nullptr : members + *found, entry};
}

void PathWriter::memberAdded(const Value& object, const Lookup& lookup) noexcept
{
    if (lookup.entry == nullptr)
    {
        return;
    }

    IndexEntry* entry = lookup.entry;
    const Member* members = &*object.MemberBegin();
    try
    {
        if (members != entry->base)
        {
            // The member array moved: re-key the same entry, updating the base its comparator reads through first
            auto node = m_index.extract(entry->base);
            node.mapped().base = members;
            node.key() = members;
            entry = &m_index.insert(std::move(node)).position->second;
        }
        const Position position = object.MemberCount() - 1; // writeAt appends the member at the end
        if (entry->indexed == position)
        {
            entry->positions.insert(position);
            ++entry->indexed;
        }
    }
    catch (...)
    {
        // The write is done: drop the entry instead of failing it. It is under `members`, or the node handle of a
        // failed re-key has already destroyed it; erasing by key does not throw
        m_index.erase(members);
    }
}

PathWriter::Value& PathWriter::write(Value& from, const Token* begin, const Token* end, Value* leaf)
{
    return internal::writeAt(
        m_doc.m_document.GetAllocator(),
        from,
        begin,
        static_cast<size_t>(end - begin),
        leaf,
        [this](Value& object, const Token& token) { return findMember(object, token); },
        [this](const Value& object, const Lookup& lookup) noexcept { memberAdded(object, lookup); },
        [this](const Value& node) noexcept { forget(node); });
}

PathWriter::Value* PathWriter::get(Value& from, const Token* begin, const Token* end) const
{
    // Mirrors rapidjson's GenericPointer::Get; only the member lookup differs
    Value* v = &from;
    for (const Token* t = begin; t != end; ++t)
    {
        switch (v->GetType())
        {
            case rapidjson::kObjectType:
            {
                auto* member = findMember(*v, *t).member;
                if (member == nullptr)
                {
                    return nullptr;
                }
                v = &member->value;
                continue;
            }
            case rapidjson::kArrayType:
                if (t->index == rapidjson::kPointerInvalidIndex || t->index >= v->Size())
                {
                    return nullptr;
                }
                v = &((*v)[t->index]);
                continue;
            default: return nullptr;
        }
    }
    return v;
}

void PathWriter::forget(const Value& target) noexcept
{
    // An object about to be overwritten drops its own entry; entries of its descendants stay until the writer dies
    if (!m_index.empty() && target.IsObject() && target.MemberCount() != 0)
    {
        m_index.erase(&*target.MemberBegin());
    }
}

void PathWriter::set(std::string_view pointerPath, const Json& value)
{
    const auto pointer = json::makePointer(pointerPath);
    if (!pointer.IsValid())
    {
        m_doc.set(pointerPath, value);
        return;
    }

    // Deep copy first: a failure leaves the document as it was
    Value copy {value.m_document, m_doc.m_document.GetAllocator()};
    write(m_doc.m_document, tokensBegin(pointer), tokensEnd(pointer), &copy);
}

void PathWriter::setStringAt(Value& from, const json::Pointer& pointer, std::string_view value)
{
    const auto* data = value.data() ? value.data() : "";
    Value v(data, static_cast<rapidjson::SizeType>(value.size()), m_doc.m_document.GetAllocator());
    write(from, tokensBegin(pointer), tokensEnd(pointer), &v);
}

void PathWriter::setString(std::string_view value, std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.setString(value, path);
        return;
    }

    setStringAt(m_doc.m_document, pointer, value);
}

void PathWriter::setStringAsMembers(std::string_view value, std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.setStringAsMembers(value, path);
        return;
    }

    const auto tokens = asMemberTokens(pointer);
    const auto* data = value.data() ? value.data() : "";
    Value v(data, static_cast<rapidjson::SizeType>(value.size()), m_doc.m_document.GetAllocator());
    write(m_doc.m_document, tokens.data(), tokens.data() + tokens.size(), &v);
}

void PathWriter::setNullAsMembers(std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.setNullAsMembers(path);
        return;
    }

    const auto tokens = asMemberTokens(pointer);
    Value v;
    write(m_doc.m_document, tokens.data(), tokens.data() + tokens.size(), &v);
}

void PathWriter::setObjectAt(Value& from, const json::Pointer& pointer)
{
    Value v(rapidjson::kObjectType);
    write(from, tokensBegin(pointer), tokensEnd(pointer), &v);
}

void PathWriter::setObject(std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.setObject(path);
        return;
    }

    setObjectAt(m_doc.m_document, pointer);
}

void PathWriter::setArray(std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.setArray(path);
        return;
    }

    Value v(rapidjson::kArrayType);
    write(m_doc.m_document, tokensBegin(pointer), tokensEnd(pointer), &v);
}

void PathWriter::appendValueAt(Value& from, const json::Pointer& pointer, Value& element)
{
    auto& allocator = m_doc.m_document.GetAllocator();
    auto* val = get(from, tokensBegin(pointer), tokensEnd(pointer));
    if (val != nullptr && val->IsArray())
    {
        val->PushBack(element, allocator); // reallocates before it touches the array
        return;
    }

    // A new array [element], built apart: it replaces the value found, or is written where the path did not exist
    Value array(rapidjson::kArrayType);
    array.PushBack(element, allocator);
    if (val != nullptr)
    {
        forget(*val);
        *val = array; // noexcept move
    }
    else
    {
        write(from, tokensBegin(pointer), tokensEnd(pointer), &array);
    }
}

void PathWriter::appendStringAt(Value& from, const json::Pointer& pointer, std::string_view value)
{
    auto& allocator = m_doc.m_document.GetAllocator();
    Value v(value.data(), static_cast<rapidjson::SizeType>(value.size()), allocator);
    appendValueAt(from, pointer, v);
}

void PathWriter::appendString(std::string_view value, std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.appendString(value, path);
        return;
    }

    const rapidjson::size_t s1 = static_cast<rapidjson::size_t>(value.size());
    const size_t s2 = static_cast<size_t>(s1);
    if (s2 != value.size())
    {
        // Json throws here; let it build the identical exception
        m_doc.appendString(value, path);
        return;
    }

    appendStringAt(m_doc.m_document, pointer, value);
}

void PathWriter::appendJsonAt(Value& from, const json::Pointer& pointer, const Json& value)
{
    auto& allocator = m_doc.m_document.GetAllocator();
    Value rapidValue {value.m_document, allocator};
    appendValueAt(from, pointer, rapidValue);
}

void PathWriter::appendJson(const Json& value, std::string_view path)
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        m_doc.appendJson(value, path);
        return;
    }

    appendJsonAt(m_doc.m_document, pointer, value);
}

bool PathWriter::existsAt(Value& from, const json::Pointer& pointer) const
{
    return get(from, tokensBegin(pointer), tokensEnd(pointer)) != nullptr;
}

bool PathWriter::exists(std::string_view pointerPath) const
{
    const auto pointer = json::makePointer(pointerPath);
    if (!pointer.IsValid())
    {
        return m_doc.exists(pointerPath);
    }
    return existsAt(m_doc.m_document, pointer);
}

bool PathWriter::isObjectAt(Value& from, const json::Pointer& pointer) const
{
    const auto* value = get(from, tokensBegin(pointer), tokensEnd(pointer));
    return value != nullptr && value->IsObject();
}

bool PathWriter::isObject(std::string_view path) const
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        return m_doc.isObject(path);
    }
    return isObjectAt(m_doc.m_document, pointer);
}

bool PathWriter::isArrayAt(Value& from, const json::Pointer& pointer) const
{
    const auto* value = get(from, tokensBegin(pointer), tokensEnd(pointer));
    return value != nullptr && value->IsArray();
}

bool PathWriter::isArray(std::string_view path) const
{
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        return m_doc.isArray(path);
    }
    return isArrayAt(m_doc.m_document, pointer);
}

std::optional<size_t> PathWriter::sizeAt(Value& from, const json::Pointer& pointer) const
{
    const auto* value = get(from, tokensBegin(pointer), tokensEnd(pointer));
    if (value != nullptr)
    {
        if (value->IsArray())
        {
            return value->Size();
        }
        if (value->IsObject())
        {
            return value->MemberCount();
        }
        if (value->IsString())
        {
            return value->GetStringLength();
        }
    }
    return std::nullopt;
}

size_t PathWriter::size(std::string_view path) const
{
    const auto pointer = json::makePointer(path);
    if (pointer.IsValid())
    {
        const auto result = sizeAt(m_doc.m_document, pointer);
        if (result.has_value())
        {
            return *result;
        }
    }
    // Invalid pointer, path not found or size not measurable: Json builds the identical exception
    return m_doc.size(path);
}

std::optional<Json> PathWriter::getJson(std::string_view path) const
{
    std::optional<Json> retval {std::nullopt};
    const auto pointer = json::makePointer(path);
    if (!pointer.IsValid())
    {
        return m_doc.getJson(path);
    }

    const auto* val = get(m_doc.m_document, tokensBegin(pointer), tokensEnd(pointer));
    if (val)
    {
        retval = Json(*val);
    }
    return retval;
}

PathWriter::Value& PathWriter::resolve(Anchor from) const
{
    if (from.m_owner != this)
    {
        throw std::runtime_error("Anchor does not belong to this PathWriter");
    }
    return *from.m_value;
}

PathWriter::Anchor PathWriter::root()
{
    return Anchor(this, &m_doc.m_document);
}

std::optional<PathWriter::Anchor> PathWriter::find(Anchor from, std::string_view relPath) const
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    auto* value = get(node, tokensBegin(pointer), tokensEnd(pointer));
    if (value == nullptr)
    {
        return std::nullopt;
    }
    return Anchor(this, value);
}

PathWriter::Anchor PathWriter::ensure(Anchor from, std::string_view relPath)
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    return Anchor(this, &write(node, tokensBegin(pointer), tokensEnd(pointer), nullptr));
}

void PathWriter::setString(Anchor from, std::string_view value, std::string_view relPath)
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    setStringAt(node, pointer, value);
}

void PathWriter::setObject(Anchor from, std::string_view relPath)
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    setObjectAt(node, pointer);
}

void PathWriter::appendString(Anchor from, std::string_view value, std::string_view relPath)
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    appendStringAt(node, pointer, value);
}

void PathWriter::appendJson(Anchor from, const Json& value, std::string_view relPath)
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    appendJsonAt(node, pointer, value);
}

bool PathWriter::exists(Anchor from, std::string_view relPath) const
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    return existsAt(node, pointer);
}

bool PathWriter::isObject(Anchor from, std::string_view relPath) const
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    return isObjectAt(node, pointer);
}

bool PathWriter::isArray(Anchor from, std::string_view relPath) const
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    return isArrayAt(node, pointer);
}

size_t PathWriter::size(Anchor from, std::string_view relPath) const
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    const auto result = sizeAt(node, pointer);
    if (!result.has_value())
    {
        throw std::runtime_error(fmt::format(
            "Size of relative path '{}' is not measurable: not found or not an array, object or string", relPath));
    }
    return *result;
}

bool PathWriter::wrapInArray(Anchor from, std::string_view relPath)
{
    auto& node = resolve(from);
    const auto pointer = relativePointer(relPath);
    checkRelativePointer(pointer, relPath);
    auto* value = get(node, tokensBegin(pointer), tokensEnd(pointer));
    if (value == nullptr)
    {
        return false;
    }

    // The array is allocated first, with the default capacity a first PushBack gives; then only noexcept moves.
    // No forget(): the moved object keeps the address of its member array, so its index entry stays valid
    Value array(rapidjson::kArrayType);
    array.PushBack(Value().Move(), m_doc.m_document.GetAllocator());
    *array.Begin() = std::move(*value);
    *value = std::move(array);
    return true;
}

size_t PathWriter::indexedObjects() const
{
    return m_index.size();
}

} // namespace json

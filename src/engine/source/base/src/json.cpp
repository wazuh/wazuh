// SPDX-License-Identifier: AGPL-3.0-or-later
#include <base/json.hpp>

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <memory_resource>
#include <new>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "rapidjson/memorystream.h"

#include <base/logging.hpp>

#include "jsonNameCompare.hpp"
#include "jsonWriteAt.hpp"

namespace
{
constexpr auto INVALID_POINTER_TYPE_MSG = "Invalid pointer path '{}'";
constexpr auto PATH_NOT_FOUND_MSG = "Path '{}' not found";

// Tokens of a parsed pointer with every one marked as an object member name. rapidjson reads a token made only of
// digits as an array index, and creating it on a node that is not an object yet reserves index + 1 elements; a name
// token turns that node into an object instead. The names still point into `pointer`, which must outlive the result.
std::vector<json::Pointer::Token> asMemberTokens(const json::Pointer& pointer)
{
    std::vector<json::Pointer::Token> tokens(pointer.GetTokens(), pointer.GetTokens() + pointer.GetTokenCount());
    for (auto& token : tokens)
    {
        token.index = rapidjson::kPointerInvalidIndex;
    }
    return tokens;
}

// `Pointer::Set` that leaves the document as it was when an allocation fails: json::internal::writeAt from the root,
// with rapidjson's linear member lookup and no hooks.
void setValue(json::Document& document, const json::Pointer::Token* tokens, size_t count, json::Value& value)
{
    json::internal::writeAt(
        document.GetAllocator(),
        document,
        tokens,
        count,
        &value,
        json::internal::findLinear,
        [](const json::Value&, const json::internal::LinearLookup&) noexcept {},
        [](const json::Value&) noexcept {});
}

void setValue(json::Document& document, const json::Pointer& pointer, json::Value& value)
{
    setValue(document, pointer.GetTokens(), pointer.GetTokenCount(), value);
}

// Exact-size copies of sub-values (Json(const json::Value&)): the pool of the new document is sized to what
// CopyFrom will allocate, instead of the 64 KB chunk of a default document. The walk below mirrors rapidjson's
// allocations; if it ever falls short the pool simply grows, it never corrupts.
static_assert(!RAPIDJSON_USE_MEMBERSMAP, "copyFootprint assumes rapidjson's flat member storage");

constexpr size_t align8(size_t bytes)
{
    return RAPIDJSON_ALIGN(bytes);
}

// Bytes the pool bookkeeping header (SharedData + ChunkHeader) takes inside a user-supplied block
size_t poolHeaderBytes()
{
    static const size_t bytes = []()
    {
        // A heap block (malloc is 16-byte aligned, like the blocks of Json(ExactTag, ...)): with a stack buffer the
        // compiler cannot tell that the allocator never frees a user-supplied block and warns
        constexpr size_t probeSize = 256;
        const std::unique_ptr<void, decltype(&std::free)> block {std::malloc(probeSize), &std::free};
        if (!block)
        {
            return probeSize;
        }
        const json::Allocator probe(block.get(), probeSize);
        const auto capacity = probe.Capacity();
        // Unexpected layout: a too large header only wastes bytes, a too small one would break the block
        return capacity < probeSize ? probeSize - capacity : probeSize;
    }();
    return bytes;
}

// Longest string rapidjson stores inline in the value (no allocation): 13 chars on x86_64, 21 on aarch64
size_t maxInlineStringLength()
{
    static const size_t length = []()
    {
        constexpr size_t maxProbe = 64;
        constexpr size_t probeChunk = 256;
        const std::string text(maxProbe, 'x');
        size_t inlineMax = 0;
        for (size_t len = 1; len <= maxProbe; ++len)
        {
            // Small chunks: the first length that allocates takes one 256-byte chunk and ends the probe
            json::Allocator probe(probeChunk);
            const json::Value value(text.data(), static_cast<rapidjson::SizeType>(len), probe);
            if (probe.Size() != 0)
            {
                return inlineMax;
            }
            inlineMax = len;
        }
        // Unexpected: nothing allocated. Count every string as allocated (a larger pool, never a smaller one)
        return size_t {0};
    }();
    return length;
}

// Bytes CopyFrom(value, allocator, true) allocates from the destination pool. The walk starts at depth 0 and stops
// past MAX_DEPTH (one level more than the parser admits); deeper levels are not counted, so the pool grows for them.
// CopyFrom itself recurses to the full depth.
size_t copyFootprint(const json::Value& value, size_t inlineMax, size_t depth)
{
    if (depth > json::Json::MAX_DEPTH)
    {
        return 0;
    }

    switch (value.GetType())
    {
        case rapidjson::kStringType:
        {
            const size_t length = value.GetStringLength();
            return length > inlineMax ? align8((length + 1) * sizeof(json::Value::Ch)) : 0;
        }
        case rapidjson::kArrayType:
        {
            size_t bytes = align8(value.Size() * sizeof(json::Value));
            for (const auto& item : value.GetArray())
            {
                bytes += copyFootprint(item, inlineMax, depth + 1);
            }
            return bytes;
        }
        case rapidjson::kObjectType:
        {
            size_t bytes = align8(value.MemberCount() * sizeof(json::Value::Member));
            for (const auto& member : value.GetObject())
            {
                bytes += copyFootprint(member.name, inlineMax, depth + 1);
                bytes += copyFootprint(member.value, inlineMax, depth + 1);
            }
            return bytes;
        }
        default: return 0;
    }
}

size_t exactPoolBytes(const json::Value& value)
{
    return copyFootprint(value, maxInlineStringLength(), 0);
}
} // namespace

namespace json
{

Json::Json(const json::Value& value)
    : Json(ExactTag {}, exactPoolBytes(value))
{
    // Const strings are copied as well: the walk counts them, and the copy must not point into the source
    m_document.CopyFrom(value, m_document.GetAllocator(), /*copyConstStrings=*/true);
}

Json::Json(const rapidjson::GenericObject<true, json::Value>& object)
    : m_document {json::Document()}
{
    m_document.SetObject();
    for (auto& [key, value] : object)
    {
        m_document.GetObject().AddMember(
            {key, m_document.GetAllocator()}, {value, m_document.GetAllocator()}, m_document.GetAllocator());
    }
}

Json::Json()
    : m_document {json::Document()} {};

Json::Json(json::Document&& document)
{
    m_document = std::move(document);
}

Json::Json(const char* json)
    : m_document {json::Document()}
{
    rapidjson::StringStream stream(json);
    rapidjson::ParseResult result = Json::parseBounded(m_document, stream);
    if (!result)
    {
        throw std::runtime_error(fmt::format("JSON document could not be parsed: {}",
                                             Json::isDepthError(result)
                                                 ? fmt::format("{} ({})", Json::DEPTH_ERROR_MSG, Json::MAX_DEPTH)
                                                 : rapidjson::GetParseError_En(result.Code())));
    }
}

Json::Json(std::string_view json)
    : m_document {json::Document()}
{
    rapidjson::MemoryStream memoryStream(json.data(), json.size());
    rapidjson::EncodedInputStream<rapidjson::UTF8<>, rapidjson::MemoryStream> stream(memoryStream);
    rapidjson::ParseResult result = Json::parseBounded(m_document, stream);
    if (!result)
    {
        throw std::runtime_error(fmt::format("JSON document could not be parsed: {}",
                                             Json::isDepthError(result)
                                                 ? fmt::format("{} ({})", Json::DEPTH_ERROR_MSG, Json::MAX_DEPTH)
                                                 : rapidjson::GetParseError_En(result.Code())));
    }
}

Json::Json(const Json& other)
    : m_document {}
{
    m_document.CopyFrom(other.m_document, m_document.GetAllocator());
}

namespace
{
/// Initial block of a compact document: max(minimum, hint rounded up to the chunk multiple).
size_t compactInitialCapacity(size_t capacityHint)
{
    if (capacityHint <= Json::COMPACT_INITIAL_CAPACITY)
    {
        return Json::COMPACT_INITIAL_CAPACITY;
    }
    constexpr auto multiple = Json::COMPACT_CHUNK_CAPACITY;
    return ((capacityHint + multiple - 1) / multiple) * multiple;
}

// Equality of two objects, or of two arrays, with the result of rapidjson's operator==; defined with the member indexes
// below.
bool containersEqual(const json::Value& lhs, const json::Value& rhs);

// Equality of two numbers with the result of rapidjson's operator==: as doubles when either side is a double (so NaN
// equals nothing), by their 64-bit pattern otherwise (so the int64 -1 equals the uint64 2^64-1). Kept out of line:
// inlined into the scans of the array merge, it made them slower.
[[gnu::noinline]] bool numbersEqual(const json::Value& lhs, const json::Value& rhs)
{
    if (lhs.IsDouble() || rhs.IsDouble())
    {
        return lhs.GetDouble() == rhs.GetDouble();
    }
    return (lhs.IsUint64() ? lhs.GetUint64() : static_cast<uint64_t>(lhs.GetInt64()))
           == (rhs.IsUint64() ? rhs.GetUint64() : static_cast<uint64_t>(rhs.GetInt64()));
}

// Equality of two values with the result of rapidjson's operator==, whose rules and shape it follows: values of
// different types differ; numbers compare as numbersEqual does; strings are equal when their lengths and bytes are;
// null, false and true equal their own type. Objects and arrays go through containersEqual, which looks object members
// up through an index once they get long.
inline bool valuesEqual(const json::Value& lhs, const json::Value& rhs)
{
    const auto type = lhs.GetType();
    if (type != rhs.GetType())
    {
        return false;
    }
    switch (type)
    {
        case rapidjson::kNumberType: return numbersEqual(lhs, rhs);
        case rapidjson::kStringType:
            return lhs.GetStringLength() == rhs.GetStringLength()
                   && std::memcmp(lhs.GetString(), rhs.GetString(), lhs.GetStringLength()) == 0;
        case rapidjson::kObjectType:
        case rapidjson::kArrayType: return containersEqual(lhs, rhs);
        default: return true;
    }
}
} // namespace

Json::Json(CompactTag, size_t capacityHint)
    : m_compactBuffer {std::make_unique<uint8_t[]>(compactInitialCapacity(capacityHint))}
    , m_ownAllocator {std::make_unique<json::Allocator>(
          m_compactBuffer.get(), compactInitialCapacity(capacityHint), COMPACT_CHUNK_CAPACITY)}
    , m_document {m_ownAllocator.get()}
{
}

Json::Json(ExactTag, size_t poolBytes)
    // new[] on purpose: make_unique<uint8_t[]> would zero the whole block, which CopyFrom overwrites anyway
    : m_compactBuffer {new uint8_t[poolHeaderBytes() + poolBytes]}
    , m_ownAllocator {std::make_unique<json::Allocator>(
          m_compactBuffer.get(), poolHeaderBytes() + poolBytes, COMPACT_CHUNK_CAPACITY)}
    , m_document {m_ownAllocator.get()}
{
}

Json Json::compact(std::string_view src, size_t capacityHint)
{
    Json result(CompactTag {}, capacityHint != 0 ? capacityHint : src.size());
    rapidjson::MemoryStream memoryStream(src.data(), src.size());
    rapidjson::EncodedInputStream<rapidjson::UTF8<>, rapidjson::MemoryStream> stream(memoryStream);
    rapidjson::ParseResult parseResult = Json::parseBounded(result.m_document, stream);
    if (!parseResult)
    {
        throw std::runtime_error(fmt::format("JSON document could not be parsed: {}",
                                             Json::isDepthError(parseResult)
                                                 ? fmt::format("{} ({})", Json::DEPTH_ERROR_MSG, Json::MAX_DEPTH)
                                                 : rapidjson::GetParseError_En(parseResult.Code())));
    }
    return result;
}

Json Json::compact() const
{
    Json result(CompactTag {}, getUsedMemory());
    result.m_document.CopyFrom(m_document, result.m_document.GetAllocator());
    return result;
}

size_t Json::getUsedMemory() const
{
    // rapidjson's GetAllocator() is non-const; Size() does not mutate the pool.
    return const_cast<Json*>(this)->m_document.GetAllocator().Size();
}

size_t Json::getAllocatedMemory() const
{
    // rapidjson's GetAllocator() is non-const; Capacity() does not mutate the pool.
    return const_cast<Json*>(this)->m_document.GetAllocator().Capacity();
}

std::string Json::formatJsonPath(std::string_view dotPath, bool skipDot)
{
    // TODO: Handle array indices and pointer path operators.
    std::string ptrPath {dotPath};

    // Some helpers may indicate that the field is root element
    // In this case the path will be defined as "."
    if (!skipDot && "." == ptrPath)
    {
        ptrPath = "";
    }
    else
    {
        // Escape the JSON Pointer special characters in one pass: '~' -> "~0", '/' -> "~1" (RFC 6901 §3).
        // The two find() calls keep the common case (nothing to escape) as cheap as a memchr scan.
        const auto first = std::min(ptrPath.find('~'), ptrPath.find('/'));
        if (first != std::string::npos)
        {
            const auto tail = ptrPath.cbegin() + static_cast<std::ptrdiff_t>(first);
            const auto specials = std::count_if(tail, ptrPath.cend(), [](char c) { return c == '~' || c == '/'; });
            std::string escaped;
            escaped.reserve(ptrPath.size() + static_cast<std::size_t>(specials));
            escaped.append(ptrPath, 0, first);
            for (auto it = tail; it != ptrPath.cend(); ++it)
            {
                const char c = *it;
                if (c == '~')
                {
                    escaped += "~0";
                }
                else if (c == '/')
                {
                    escaped += "~1";
                }
                else
                {
                    escaped += c;
                }
            }
            ptrPath = std::move(escaped);
        }

        // Replace . with /
        if (!skipDot)
        {
            std::string result;
            result.reserve(ptrPath.size()); // To avoid unnecessary relocations
            bool prevCharWasSlash = false;

            for (char c : ptrPath)
            {
                if (c == '.' && !prevCharWasSlash)
                {
                    result += '/';
                }
                else if (c != '\\' || ((c == '.' || c == '\\') && prevCharWasSlash))
                {
                    result += c;
                }
                prevCharWasSlash = (c == '\\');
            }
            ptrPath = std::move(result);
        }

        // Add / at the beginning
        if (ptrPath.empty())
        {
            ptrPath = "/";
        }
        else if (ptrPath.front() != '/')
        {
            ptrPath.insert(0, "/");
        }
    }

    return ptrPath;
}

Json::Json(Json&& other) noexcept
    : m_compactBuffer {std::move(other.m_compactBuffer)}
    , m_ownAllocator {std::move(other.m_ownAllocator)}
    , m_document {std::move(other.m_document)}
{
    // The moved document keeps its internal pointer to the allocator; moving the
    // unique_ptrs preserves the allocator's (heap) address, so it stays valid.
}

Json& Json::operator=(Json&& other) noexcept
{
    // Release our document first (it may reference our current allocator), then take
    // ownership of the other's allocator and its backing buffer.
    m_document = std::move(other.m_document);
    m_ownAllocator = std::move(other.m_ownAllocator);
    m_compactBuffer = std::move(other.m_compactBuffer);
    return *this;
}

bool Json::exists(std::string_view ptrPath) const
{
    const auto fieldPtr = json::makePointer(ptrPath);
    if (fieldPtr.IsValid())
    {
        return fieldPtr.Get(m_document) != nullptr;
    }

    throw std::runtime_error(fmt::format("..", __func__, ptrPath));
}

bool operator==(const Json& lhs, const Json& rhs)
{
    return valuesEqual(lhs.m_document, rhs.m_document);
}

bool Json::equals(std::string_view ptrPath, const Json& value) const
{
    const auto fieldPtr = json::makePointer(ptrPath);
    if (fieldPtr.IsValid())
    {
        const auto got {fieldPtr.Get(m_document)};
        return (got && valuesEqual(*got, value.m_document));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
}

bool Json::equalsString(std::string_view ptrPath, std::string_view str) const
{
    const auto fieldPtr = json::makePointer(ptrPath);
    if (fieldPtr.IsValid())
    {
        const auto got {fieldPtr.Get(m_document)};
        if (!got || !got->IsString())
        {
            return false;
        }
        return std::string_view(got->GetString(), got->GetStringLength()) == str;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
}

bool Json::equals(std::string_view basePtrPath, std::string_view referencePtrPath) const
{
    const auto fieldPtr = json::makePointer(basePtrPath);
    const auto referencePtr = json::makePointer(referencePtrPath);

    if (!fieldPtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, basePtrPath));
    }
    if (!referencePtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, referencePtrPath));
    }

    const auto fieldValue {fieldPtr.Get(m_document)};
    const auto referenceValue {referencePtr.Get(m_document)};

    return (fieldValue && referenceValue && valuesEqual(*fieldValue, *referenceValue));
}

// TODO Invert parameters to be consistent with other methods.
void Json::set(std::string_view ptrPath, const Json& value)
{
    const auto fieldPtr = json::makePointer(ptrPath);
    if (fieldPtr.IsValid())
    {
        // The copy is complete before the target node is touched: an allocation failure leaves the document as it was
        json::Value copy {value.m_document, m_document.GetAllocator()};
        setValue(m_document, fieldPtr, copy);
    }
    else
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
    }
}

void Json::set(std::string_view basePtrPath, std::string_view referencePtrPath)
{
    const auto fieldPtr = json::makePointer(basePtrPath);
    const auto referencePtr = json::makePointer(referencePtrPath);

    if (!fieldPtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, basePtrPath));
    }
    if (!referencePtr.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, referencePtrPath));
    }

    const auto* reference = referencePtr.Get(m_document);
    if (reference)
    {
        // Copied before the target is created: the copy cannot fail halfway, and the reference stays valid while
        // the target path grows the tree
        json::Value copy {*reference, m_document.GetAllocator()};
        setValue(m_document, fieldPtr, copy);
    }
    else
    {
        json::Value null;
        setValue(m_document, fieldPtr, null);
    }
}

bool Json::anyMemberName(const std::function<bool(std::string_view)>& predicate, const PointerPath& path) const
{
    const auto* value = path.getPointer().Get(m_document);
    if (!value || !value->IsObject())
    {
        return false;
    }
    for (auto member = value->MemberBegin(); member != value->MemberEnd(); ++member)
    {
        if (predicate(std::string_view(member->name.GetString(), member->name.GetStringLength())))
        {
            return true;
        }
    }
    return false;
}

RetGet Json::getUniqueString(std::string_view& out, const PointerPath& path) const noexcept
{
    const auto& pointer = path.getPointer();
    const auto* value = static_cast<const json::Value*>(&m_document);
    for (rapidjson::SizeType i = 0; i < pointer.GetTokenCount(); ++i)
    {
        if (!value->IsObject())
        {
            return RetGet::WrongType;
        }
        const auto& token = pointer.GetTokens()[i];
        const std::string_view name {token.name, token.length};
        const json::Value* found = nullptr;
        for (auto member = value->MemberBegin(); member != value->MemberEnd(); ++member)
        {
            if (std::string_view(member->name.GetString(), member->name.GetStringLength()) != name)
            {
                continue;
            }
            if (found)
            {
                return RetGet::NotFound;
            }
            found = &member->value;
        }
        if (!found)
        {
            return RetGet::NotFound;
        }
        value = found;
    }
    if (!value->IsString())
    {
        return RetGet::WrongType;
    }
    out = std::string_view(value->GetString(), value->GetStringLength());
    return RetGet::Success;
}

std::optional<int> Json::getInt(std::string_view path) const
{
    std::optional<int> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsInt())
        {
            retval = value->GetInt();
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<int64_t> Json::getInt64(std::string_view path) const
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsInt64())
        {
            return value->GetInt64();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] Invalid json path: '{}'", path));
    }
}

std::optional<uint64_t> Json::getUint64(std::string_view path) const
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsUint64())
        {
            return value->GetUint64();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] Invalid json path: '{}'", path));
    }
}

std::optional<int64_t> Json::getIntAsInt64(std::string_view path) const
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsInt64())
        {
            return value->GetInt64();
        }
        else if (value && value->IsInt())
        {
            return static_cast<int64_t>(value->GetInt());
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] Invalid json path: '{}'", path));
    }
}

std::optional<float_t> Json::getFloat(std::string_view path) const
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsFloat())
        {
            return value->GetFloat();
        }
        else
        {
            return std::nullopt;
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::get(basePointerPath)] Invalid json path: '{}'", path));
    }
}

std::optional<double_t> Json::getDouble(std::string_view path) const
{
    std::optional<double> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsDouble())
        {
            retval = value->GetDouble();
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<double> Json::getNumberAsDouble(std::string_view path) const
{
    std::optional<double> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsNumber())
        {
            if (value->IsInt())
            {
                retval = static_cast<double>(value->GetInt());
            }
            else if (value->IsInt64())
            {
                retval = static_cast<double>(value->GetInt64());
            }
            else if (value->IsDouble())
            {
                retval = value->GetDouble();
            }
            else if (value->IsFloat())
            {
                retval = value->GetFloat();
            }
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<bool> Json::getBool(std::string_view path) const
{
    std::optional<bool> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsBool())
        {
            retval = value->GetBool();
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<std::vector<Json>> Json::getArray(std::string_view path) const
{
    std::optional<std::vector<Json>> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsArray())
        {
            std::vector<Json> result;
            result.reserve(value->Size());
            for (const auto& item : value->GetArray())
            {
                result.push_back(Json(item));
            }
            retval = std::move(result);
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<std::vector<std::tuple<std::string, Json>>> Json::getObject(std::string_view path) const
{
    std::optional<std::vector<std::tuple<std::string, Json>>> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value && value->IsObject())
        {
            std::vector<std::tuple<std::string, Json>> result;
            result.reserve(value->MemberCount());
            for (auto& [key, value] : value->GetObject())
            {
                result.emplace_back(std::make_tuple(key.GetString(), Json(value)));
            }
            retval = std::move(result);
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::unordered_map<std::string, Json> Json::extractObjectMembers()
{
    if (!m_document.IsObject())
    {
        throw std::runtime_error("extractObjectMembers called on non-object Json");
    }

    std::unordered_map<std::string, Json> result;
    result.reserve(m_document.MemberCount());

    for (auto& m : m_document.GetObject())
    {
        Json entry;
        entry.m_document.Swap(m.value); // Zero-copy: steals value, leaves null in source
        result.try_emplace(std::string(m.name.GetString(), m.name.GetStringLength()), std::move(entry));
    }

    return result;
}

std::optional<std::vector<std::string>> Json::getFields() const
{
    std::optional<std::vector<std::string>> retval {std::nullopt};

    if (m_document.IsObject())
    {
        std::vector<std::string> result;
        auto nested = [&](const auto& self, const json::Value& value, const std::string& path = "") -> void
        {
            for (auto& [key, value] : value.GetObject())
            {
                std::string newPath = [&]() -> std::string
                {
                    if (path.empty())
                    {
                        return key.GetString();
                    }
                    else
                    {
                        return path + "." + key.GetString();
                    }
                }();

                if (value.IsObject())
                {
                    self(self, value, newPath);
                }
                else
                {
                    result.push_back(newPath);
                }
            }
        };

        nested(nested, m_document);
        retval = std::move(result);
    }

    return retval;
}

std::optional<std::vector<std::string>> Json::getFields(std::string_view path) const
{
    const auto pp = json::makePointer(path);
    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    const json::Value* val = pp.Get(m_document);
    if (val == nullptr || !val->IsObject())
    {
        return std::nullopt;
    }

    std::vector<std::string> out;
    out.reserve(val->MemberCount());
    for (auto it = val->MemberBegin(); it != val->MemberEnd(); ++it)
    {
        out.emplace_back(it->name.GetString(), it->name.GetStringLength());
    }
    return out;
}

namespace
{
using PlainWriter =
    rapidjson::Writer<json::StringBuffer, json::Document::EncodingType, rapidjson::ASCII<>, json::BaseAllocator>;
using PrettyWriter =
    rapidjson::PrettyWriter<json::StringBuffer, json::Document::EncodingType, rapidjson::ASCII<>, json::BaseAllocator>;

constexpr std::string_view REPLACEMENT_CHAR {"\xEF\xBF\xBD"}; // U+FFFD

// Bytes that rapidjson::UTF8<>::Decode reads after a lead byte of each range type (encodings.h), valid or not.
unsigned continuationBytes(unsigned char lead)
{
    switch (rapidjson::UTF8<>::GetRange(lead))
    {
        case 2: return 1;
        case 3:
        case 4:
        case 10: return 2;
        case 5:
        case 6:
        case 11: return 3;
        default: return 0;
    }
}

// The writer decodes a string through an unbounded stream and keeps reading continuation bytes after a lead byte
// even when the sequence is invalid, so a lead byte whose sequence does not fit inside the string reads past its
// end. Only the last three bytes can start such a sequence. The check is deliberately conservative: it also
// rejects a sequence that would only read the terminator, and a lead byte that an earlier sequence would have
// consumed; those strings just take the sanitizing pass.
inline bool tailIsSafe(const char* str, rapidjson::SizeType length)
{
    // Fast path: an ASCII tail (the common case) is safe; one test over the last three bytes, no branch per byte
    const auto* bytes = reinterpret_cast<const unsigned char*>(str);
    if (length >= 3 && ((bytes[length - 1] | bytes[length - 2] | bytes[length - 3]) & 0x80) == 0)
    {
        return true;
    }

    for (rapidjson::SizeType pos = length > 3 ? length - 3 : 0; pos < length; ++pos)
    {
        const auto byte = static_cast<unsigned char>(str[pos]);
        // pos < length here, so the subtraction cannot wrap (an addition could, for a string near SizeType's limit)
        if (byte >= 0x80 && continuationBytes(byte) >= length - pos)
        {
            return false;
        }
    }

    return true;
}

// Forwards every SAX event to the writer. The string events are overridden by the two handlers below.
template<typename Writer>
class ForwardingHandler
{
public:
    using Ch = char;

    explicit ForwardingHandler(Writer& writer)
        : m_writer(writer)
    {
    }

    bool Null() { return m_writer.Null(); }
    bool Bool(bool value) { return m_writer.Bool(value); }
    bool Int(int value) { return m_writer.Int(value); }
    bool Uint(unsigned value) { return m_writer.Uint(value); }
    bool Int64(int64_t value) { return m_writer.Int64(value); }
    bool Uint64(uint64_t value) { return m_writer.Uint64(value); }
    bool Double(double value) { return m_writer.Double(value); }
    bool RawNumber(const Ch* str, rapidjson::SizeType length, bool copy)
    {
        return m_writer.RawNumber(str, length, copy);
    }
    bool StartObject() { return m_writer.StartObject(); }
    bool EndObject(rapidjson::SizeType memberCount) { return m_writer.EndObject(memberCount); }
    bool StartArray() { return m_writer.StartArray(); }
    bool EndArray(rapidjson::SizeType elementCount) { return m_writer.EndArray(elementCount); }

protected:
    Writer& m_writer;
};

// First pass: the writer's own output, as long as no string could make it read past its end.
template<typename Writer>
class TailCheckingHandler : public ForwardingHandler<Writer>
{
public:
    using Ch = char;
    using ForwardingHandler<Writer>::ForwardingHandler;

    bool String(const Ch* str, rapidjson::SizeType length, bool copy)
    {
        return tailIsSafe(str, length) && this->m_writer.String(str, length, copy);
    }
    bool Key(const Ch* str, rapidjson::SizeType length, bool copy)
    {
        return tailIsSafe(str, length) && this->m_writer.Key(str, length, copy);
    }
};

// Replaces every byte that does not start a valid UTF-8 sequence with U+FFFD (the same policy as the agent's
// w_utf8_filter). Returns whether anything was replaced; `clean` holds the result only in that case.
bool sanitizeUtf8(const char* str, rapidjson::SizeType length, std::string& clean)
{
    bool changed = false;

    for (rapidjson::SizeType pos = 0; pos < length;)
    {
        rapidjson::SizeType consumed = 1;
        bool valid = true;
        if (static_cast<unsigned char>(str[pos]) >= 0x80)
        {
            // Bounded by the string length: Take() yields '\0' at the end instead of reading past it.
            rapidjson::MemoryStream stream(str + pos, length - pos);
            unsigned codepoint = 0;
            valid = rapidjson::UTF8<>::Decode(stream, &codepoint);
            consumed = static_cast<rapidjson::SizeType>(stream.Tell());
        }

        if (valid)
        {
            if (changed)
            {
                clean.append(str + pos, consumed);
            }
            pos += consumed;
        }
        else
        {
            if (!changed)
            {
                clean.assign(str, pos);
                changed = true;
            }
            clean.append(REPLACEMENT_CHAR);
            // Decode consumes the whole expected sequence even when it is invalid; resynchronize one byte later
            ++pos;
        }
    }

    return changed;
}

using NameSet = std::unordered_set<std::string>;

// The valid (unchanged) member names of every object, in the order Accept() visits the objects (document order,
// parents before their children). A sanitized key must not collide with any of them.
void collectValidNames(const json::Value& value, std::vector<NameSet>& names)
{
    if (value.IsObject())
    {
        const auto index = names.size();
        names.emplace_back();
        for (auto it = value.MemberBegin(); it != value.MemberEnd(); ++it)
        {
            std::string clean;
            if (!sanitizeUtf8(it->name.GetString(), it->name.GetStringLength(), clean))
            {
                names[index].emplace(it->name.GetString(), it->name.GetStringLength());
            }
            collectValidNames(it->value, names);
        }
    }
    else if (value.IsArray())
    {
        for (auto it = value.Begin(); it != value.End(); ++it)
        {
            collectValidNames(*it, names);
        }
    }
}

// Second pass: strings and keys go through sanitizeUtf8 and every non-finite number becomes null, so the output
// always parses. A sanitized key whose name collides with a valid sibling (anywhere in the object) or with a
// sanitized sibling already written would duplicate the name, which the indexer rejects: that member, value
// included, is dropped instead. Valid keys are never renamed or dropped.
template<typename Writer>
class SanitizingHandler : public ForwardingHandler<Writer>
{
public:
    using Ch = char;

    SanitizingHandler(Writer& writer, const json::Value& root)
        : ForwardingHandler<Writer>(writer)
    {
        collectValidNames(root, m_validNames);
    }

    bool Null() { return skipping() || this->m_writer.Null(); }
    bool Bool(bool value) { return skipping() || this->m_writer.Bool(value); }
    bool Int(int value) { return skipping() || this->m_writer.Int(value); }
    bool Uint(unsigned value) { return skipping() || this->m_writer.Uint(value); }
    bool Int64(int64_t value) { return skipping() || this->m_writer.Int64(value); }
    bool Uint64(uint64_t value) { return skipping() || this->m_writer.Uint64(value); }
    bool Double(double value)
    {
        return skipping() || (std::isfinite(value) ? this->m_writer.Double(value) : this->m_writer.Null());
    }
    bool RawNumber(const Ch* str, rapidjson::SizeType length, bool copy)
    {
        return skipping() || this->m_writer.RawNumber(str, length, copy);
    }

    bool String(const Ch* str, rapidjson::SizeType length, bool copy)
    {
        if (skipping())
        {
            return true;
        }
        std::string clean;
        return sanitizeUtf8(str, length, clean)
                   ? this->m_writer.String(clean.data(), static_cast<rapidjson::SizeType>(clean.size()), true)
                   : this->m_writer.String(str, length, copy);
    }

    bool Key(const Ch* str, rapidjson::SizeType length, bool copy)
    {
        if (m_skipDepth > 0)
        {
            return true; // a key inside the dropped value
        }
        std::string clean;
        if (!sanitizeUtf8(str, length, clean))
        {
            return this->m_writer.Key(str, length, copy);
        }

        const auto& valid = m_validNames[m_objectIndex.back()];
        auto& written = m_writtenNames.back();
        if (valid.count(clean) != 0 || !written.insert(clean).second)
        {
            LOG_DEBUG("[Json] Dropped a member whose sanitized key collides with a sibling key");
            m_skipDepth = 1; // the member's value follows: skip it whole
            return true;
        }
        return this->m_writer.Key(clean.data(), static_cast<rapidjson::SizeType>(clean.size()), true);
    }

    bool StartObject()
    {
        if (m_skipDepth > 0)
        {
            // collectValidNames counted this object too: keep the index in step with the traversal
            ++m_nextObject;
            ++m_skipDepth;
            return true;
        }
        m_objectIndex.push_back(m_nextObject++);
        m_writtenNames.emplace_back();
        return this->m_writer.StartObject();
    }
    bool EndObject(rapidjson::SizeType memberCount)
    {
        if (m_skipDepth > 0)
        {
            closeSkipped();
            return true;
        }
        m_objectIndex.pop_back();
        m_writtenNames.pop_back();
        return this->m_writer.EndObject(memberCount);
    }
    bool StartArray()
    {
        if (m_skipDepth > 0)
        {
            ++m_skipDepth;
            return true;
        }
        return this->m_writer.StartArray();
    }
    bool EndArray(rapidjson::SizeType elementCount)
    {
        if (m_skipDepth > 0)
        {
            closeSkipped();
            return true;
        }
        return this->m_writer.EndArray(elementCount);
    }

private:
    // A dropped member's value is skipped whole. m_skipDepth is 1 while the value is pending, one more per container
    // opened inside it: a scalar at depth 1 is the whole value, and closing the container that brings the depth back
    // to 1 ends the skip. Called for every scalar event: consumes it while skipping.
    bool skipping()
    {
        if (m_skipDepth == 0)
        {
            return false;
        }
        if (m_skipDepth == 1)
        {
            m_skipDepth = 0; // the scalar was the whole value
        }
        return true;
    }

    void closeSkipped()
    {
        if (--m_skipDepth == 1)
        {
            m_skipDepth = 0; // the container was the whole value
        }
    }

    std::vector<NameSet> m_validNames;      // per object, in visiting order
    std::vector<std::size_t> m_objectIndex; // stack: index into m_validNames of each open object
    std::vector<NameSet> m_writtenNames;    // stack: sanitized names already written in each open object
    std::size_t m_nextObject {0};
    unsigned m_skipDepth {0};
};

std::atomic<bool> g_sanitizedOnce {false};

// The fast path is a single traversal with the writer's own output. Only a document the writer cannot serialize
// (invalid UTF-8 or a non-finite number) takes the second, sanitizing traversal: a truncated document is never
// returned, because the indexer rejects it and the event would be lost.
template<typename Writer>
std::string serialize(const json::Value& value)
{
    {
        json::StringBuffer buffer;
        Writer writer(buffer);
        TailCheckingHandler<Writer> handler(writer);
        if (value.Accept(handler))
        {
            return buffer.GetString();
        }
    }

    json::StringBuffer buffer;
    Writer writer(buffer);
    SanitizingHandler<Writer> handler(writer, value);
    if (!value.Accept(handler))
    {
        LOG_ERROR("[Json] Cannot serialize a document even after replacing its invalid UTF-8 and non-finite numbers");
        throw std::runtime_error("Json serialization failed after sanitizing the document");
    }

    if (!g_sanitizedOnce.exchange(true, std::memory_order_relaxed))
    {
        LOG_WARNING("[Json] Serialized a document with invalid UTF-8 or a non-finite number: the invalid bytes were "
                    "replaced with U+FFFD and the numbers with null. Further occurrences are logged at debug level");
    }
    else
    {
        LOG_DEBUG("[Json] Serialized a document with invalid UTF-8 or a non-finite number (replaced with U+FFFD/null)");
    }

    return buffer.GetString();
}
} // namespace

std::string Json::prettyStr() const
{
    return serialize<PrettyWriter>(m_document);
}

std::string Json::str() const
{
    return serialize<PlainWriter>(m_document);
}

std::optional<std::string> Json::str(std::string_view path) const
{
    std::optional<std::string> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto& value = pp.Get(m_document);
        if (value)
        {
            retval = serialize<PlainWriter>(*value);
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::ostream& operator<<(std::ostream& os, const Json& json)
{
    os << json.str();
    return os;
}

size_t Json::size(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            if (value->IsArray())
            {
                return value->Size();
            }
            else if (value->IsObject())
            {
                return value->MemberCount();
            }
            else if (value->IsString())
            {
                // TODO: create tests
                return value->GetStringLength();
            }
            throw std::runtime_error(fmt::format("Size of field '{}' is not measurable.", path));
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isNull(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsNull();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isBool(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsBool();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isNumber(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsNumber();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isInt(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsInt();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isUint64(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsUint64();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isInt64(std::string_view path) const
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsInt64();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isFloat(std::string_view path) const
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsFloat();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isDouble(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsDouble();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isString(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsString();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isArray(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsArray();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isObject(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return value->IsObject();
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

bool Json::isEmpty(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            if (value->IsArray())
            {
                return value->Empty();
            }
            else if (value->IsObject())
            {
                return value->ObjectEmpty();
            }
            else if (value->IsString())
            {
                return value->GetStringLength() == 0;
            }
            else if (value->IsNumber())
            {
                return value->GetDouble() == 0;
            }
            else if (value->IsBool())
            {
                return !value->GetBool();
            }
            else if (value->IsNull())
            {
                return true;
            }
        }

        return false;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::string Json::typeName(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            switch (value->GetType())
            {
                case rapidjson::kNullType: return "null";
                case rapidjson::kFalseType:
                case rapidjson::kTrueType: return "bool";
                case rapidjson::kNumberType: return "number";
                case rapidjson::kStringType: return "string";
                case rapidjson::kArrayType: return "array";
                case rapidjson::kObjectType: return "object";
                default: return "unknown";
            }
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

Json::Type Json::type(std::string_view path) const
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* value = pp.Get(m_document);
        if (value)
        {
            return rapidTypeToJsonType(value->GetType());
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setNull(std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value null;
        setValue(m_document, pp, null);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setBool(bool value, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value v(value);
        setValue(m_document, pp, v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setInt(int value, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value v(value);
        setValue(m_document, pp, v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setInt64(int64_t value, std::string_view path)
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value v(value);
        setValue(m_document, pp, v);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setInt(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setUint64(uint64_t value, std::string_view path)
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value v(value);
        setValue(m_document, pp, v);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setUint64(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setFloat(float_t value, std::string_view path)
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value v(value);
        setValue(m_document, pp, v);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setDouble(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setDouble(double_t value, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value v(value);
        setValue(m_document, pp, v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setStringAsMembers(std::string_view value, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto tokens = asMemberTokens(pp);
        const auto* data = value.data() ? value.data() : "";
        json::Value v(data, static_cast<rapidjson::SizeType>(value.size()), m_document.GetAllocator());
        setValue(m_document, tokens.data(), tokens.size(), v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setNullAsMembers(std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto tokens = asMemberTokens(pp);
        json::Value null;
        setValue(m_document, tokens.data(), tokens.size(), null);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setString(std::string_view value, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        const auto* data = value.data() ? value.data() : "";
        json::Value v(data, static_cast<rapidjson::SizeType>(value.size()), m_document.GetAllocator());
        setValue(m_document, pp, v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setArray(std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value arr(rapidjson::kArrayType);
        setValue(m_document, pp, arr);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setObject(std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value obj(rapidjson::kObjectType);
        setValue(m_document, pp, obj);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::appendString(std::string_view value, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        // TODO: not sure if needed, add test
        const rapidjson::size_t s1 = static_cast<rapidjson::size_t>(value.size());
        const size_t s2 = static_cast<size_t>(s1);
        if (s2 != value.size())
        {
            throw std::runtime_error(fmt::format("String is too long ({}): '{}'.", value.size(), value));
        }
        json::Value v(value.data(), s2, m_document.GetAllocator());

        auto* val = pp.Get(m_document);
        if (val)
        {
            if (val->IsArray())
            {
                val->PushBack(v, m_document.GetAllocator());
            }
            else
            {
                // Built apart so that an allocation failure leaves the scalar in place
                json::Value arr(rapidjson::kArrayType);
                arr.PushBack(v, m_document.GetAllocator());
                *val = arr;
            }
        }
        else
        {
            json::Value vArray;
            vArray.SetArray();
            vArray.PushBack(v, m_document.GetAllocator());
            setValue(m_document, pp, vArray);
        }
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::appendJson(const Json& value, std::string_view path)
{
    auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        json::Value rapidValue {value.m_document, m_document.GetAllocator()};
        auto* val = pp.Get(m_document);
        if (val)
        {
            if (val->IsArray())
            {
                val->PushBack(rapidValue, m_document.GetAllocator());
            }
            else
            {
                json::Value arr(rapidjson::kArrayType);
                arr.PushBack(rapidValue, m_document.GetAllocator());
                *val = arr;
            }
        }
        else
        {
            json::Value vArray;
            vArray.SetArray();
            vArray.PushBack(rapidValue, m_document.GetAllocator());
            setValue(m_document, pp, vArray);
        }
    }
    else
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }
}

bool Json::erase(std::string_view path)
{
    if (path.empty())
    {
        m_document.SetNull();
        return true;
    }
    else
    {
        const auto pp = json::makePointer(path);

        if (pp.IsValid())
        {
            return pp.Erase(m_document);
        }

        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }
}

namespace
{

using Position = rapidjson::SizeType;

std::string_view memberName(const json::Value& name)
{
    return {name.GetString(), name.GetStringLength()};
}

// Orders member positions of an object by name. The names are read through the live object on every comparison, so
// the positions stay valid when AddMember moves the member array.
struct MemberPositionLess
{
    using is_transparent = void;

    const json::Value* object;

    std::string_view nameAt(Position position) const { return memberName((object->MemberBegin() + position)->name); }

    bool operator()(Position lhs, Position rhs) const { return internal::compareNames(nameAt(lhs), nameAt(rhs)) < 0; }
    bool operator()(Position lhs, std::string_view rhs) const { return internal::compareNames(nameAt(lhs), rhs) < 0; }
    bool operator()(std::string_view lhs, Position rhs) const { return internal::compareNames(lhs, nameAt(rhs)) < 0; }
};

// The positions of the members of an object ordered by name, first occurrence of each name only. Its nodes come from
// a buffer that is released at once.
struct MemberIndex
{
    std::pmr::monotonic_buffer_resource memory;
    std::pmr::set<Position, MemberPositionLess> positions;

    explicit MemberIndex(const json::Value& object)
        : positions(MemberPositionLess {&object}, &memory)
    {
        const Position count = object.MemberCount();
        for (Position position = 0; position < count; ++position)
        {
            positions.insert(positions.end(), position);
        }
    }
};

// Position of the first of the count members with that name, or count if there is none: the lookup of rapidjson's
// FindMember. The caller passes the members and their count so that a loop of lookups reads them once.
inline Position firstPositionOf(json::Value::ConstMemberIterator members, Position count, std::string_view name)
{
    Position position = 0;
    while (position < count && memberName(members[position].name) != name)
    {
        ++position;
    }
    return position;
}

// The members of lhs from lhsIt on are equal to those of rhs, each looked up through a hash index of rhs that holds the
// first occurrence of each name, like FindMember. A hash index, unlike the ordered MemberIndex, costs few enough name
// comparisons to build that a comparison is not noticeably slower than scanning where the budget hands over. Its nodes
// come from a buffer that is released at once. If the index cannot be allocated, the rest is looked up by scanning, so
// a comparison never throws std::bad_alloc. Kept out of line so that the comparisons that never need the index do not
// carry it.
[[gnu::noinline]] bool
objectsEqualIndexed(const json::Value& lhs, const json::Value& rhs, json::Value::ConstMemberIterator lhsIt)
{
    const Position count = rhs.MemberCount();
    const auto rhsMembers = rhs.MemberBegin();
    std::pmr::monotonic_buffer_resource memory;
    std::pmr::unordered_map<std::string_view, Position> firstByName(&memory);
    try
    {
        firstByName.reserve(count);
        for (Position position = 0; position < count; ++position)
        {
            firstByName.try_emplace(memberName(rhsMembers[position].name), position);
        }
    }
    catch (const std::bad_alloc&)
    {
        for (; lhsIt != lhs.MemberEnd(); ++lhsIt)
        {
            const auto position = firstPositionOf(rhsMembers, count, memberName(lhsIt->name));
            if (position == count || !valuesEqual(lhsIt->value, rhsMembers[position].value))
            {
                return false;
            }
        }
        return true;
    }
    for (; lhsIt != lhs.MemberEnd(); ++lhsIt)
    {
        const auto found = firstByName.find(memberName(lhsIt->name));
        if (found == firstByName.end() || !valuesEqual(lhsIt->value, rhsMembers[found->second].value))
        {
            return false;
        }
    }
    return true;
}

// Objects of the same type, compared as rapidjson's operator== does: same number of members, and every member of lhs
// equal to the first member of rhs with its name.
bool objectsEqual(const json::Value& lhs, const json::Value& rhs)
{
    const Position count = rhs.MemberCount();
    if (lhs.MemberCount() != count)
    {
        return false;
    }

    // Names compared by the scans of this loop. Once they exceed EQUALS_INDEX_SCAN_FACTOR times the number of members,
    // the rest of lhs is looked up through an index of rhs.
    size_t scanned = 0;
    const auto rhsMembers = rhs.MemberBegin();
    for (auto lhsIt = lhs.MemberBegin(); lhsIt != lhs.MemberEnd(); ++lhsIt)
    {
        if (scanned > Json::EQUALS_INDEX_SCAN_FACTOR * static_cast<size_t>(count))
        {
            return objectsEqualIndexed(lhs, rhs, lhsIt);
        }

        const auto position = firstPositionOf(rhsMembers, count, memberName(lhsIt->name));
        scanned += position + 1;
        if (position == count || !valuesEqual(lhsIt->value, rhsMembers[position].value))
        {
            return false;
        }
    }
    return true;
}

bool containersEqual(const json::Value& lhs, const json::Value& rhs)
{
    if (lhs.IsObject())
    {
        return objectsEqual(lhs, rhs);
    }
    const auto size = lhs.Size();
    if (size != rhs.Size())
    {
        return false;
    }
    for (rapidjson::SizeType i = 0; i < size; ++i)
    {
        if (!valuesEqual(lhs[i], rhs[i]))
        {
            return false;
        }
    }
    return true;
}

void mergeValue(json::Value& dst, const json::Value& src, bool isRecursive, json::Allocator& allocator);

// Merges one source member into the object dst once its member in dst (or MemberEnd) is known. Returns true if the
// member was added.
bool mergeMember(json::Value& dst,
                 json::Value::MemberIterator found,
                 json::Value::ConstMemberIterator srcIt,
                 bool isRecursive,
                 json::Allocator& allocator)
{
    if (found != dst.MemberEnd())
    {
        json::Value cpyValue {srcIt->value, allocator};
        if (isRecursive && (srcIt->value.IsObject() || srcIt->value.IsArray()))
        {
            mergeValue(found->value, cpyValue, isRecursive, allocator);
        }
        else
        {
            found->value = cpyValue;
        }
        return false;
    }

    json::Value cpyValue {srcIt->value, allocator};
    json::Value cpyName {srcIt->name, allocator};
    dst.AddMember(cpyName, cpyValue, allocator);
    return true;
}

// Merges the source members from srcIt on into the object dst, looking them up through an index of dst: it holds the
// first occurrence of each name, like FindMember, and every member added from here on. Kept out of line so that the
// merges that never need the index do not carry it.
[[gnu::noinline]] void mergeMembersIndexed(json::Value& dst,
                                           const json::Value& src,
                                           json::Value::ConstMemberIterator srcIt,
                                           bool isRecursive,
                                           json::Allocator& allocator)
{
    MemberIndex index(dst);
    for (; srcIt != src.MemberEnd(); ++srcIt)
    {
        auto found = dst.MemberEnd();
        const auto position = index.positions.find(memberName(srcIt->name));
        if (position != index.positions.end())
        {
            found = dst.MemberBegin() + *position;
        }
        if (mergeMember(dst, found, srcIt, isRecursive, allocator))
        {
            index.positions.insert(index.positions.end(), dst.MemberCount() - 1);
        }
    }
}

uint64_t mixHash(uint64_t x)
{
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

uint64_t hashBytes(std::string_view bytes)
{
    return static_cast<uint64_t>(std::hash<std::string_view> {}(bytes));
}

// True if a name appears more than once among the members of object.
bool hasRepeatedName(const json::Value& object)
{
    const Position count = object.MemberCount();
    const auto members = object.MemberBegin();
    if (count <= 8)
    {
        for (Position lhs = 0; lhs < count; ++lhs)
        {
            for (Position rhs = lhs + 1; rhs < count; ++rhs)
            {
                if (memberName(members[lhs].name) == memberName(members[rhs].name))
                {
                    return true;
                }
            }
        }
        return false;
    }

    std::vector<std::string_view> names;
    names.reserve(count);
    for (Position position = 0; position < count; ++position)
    {
        names.push_back(memberName(members[position].name));
    }
    std::sort(names.begin(), names.end());
    return std::adjacent_find(names.begin(), names.end()) != names.end();
}

// Hash of a value for the lookups of the array merge, which compares elements with rapidjson's operator==. That
// operator is not an equivalence: numbers compare as doubles when either side is one, and by bit pattern otherwise,
// so a uint64 above INT64_MAX equals the negative int64 with the same bits; objects look each member of the left side
// up by its first occurrence in the right side, so with a repeated name an object can equal one with other names.
// Values that hold neither (regular) compare equal only when they are structurally equal with numbers compared as
// doubles and objects as maps, so equal regular values get equal hashes here: numbers are hashed through their double,
// with -0.0 as 0.0, and objects as an order-independent sum. Values that hold either are flagged irregular, and their
// hash is not used.
struct ElementHash
{
    uint64_t hash;
    bool irregular;
};

ElementHash hashElement(const json::Value& value)
{
    switch (value.GetType())
    {
        case rapidjson::kNullType: return {mixHash(1), false};
        case rapidjson::kFalseType: return {mixHash(2), false};
        case rapidjson::kTrueType: return {mixHash(3), false};
        case rapidjson::kStringType: return {mixHash(4 ^ hashBytes(memberName(value))), false};
        case rapidjson::kNumberType:
        {
            double number = value.GetDouble();
            if (number == 0.0)
            {
                number = 0.0;
            }
            uint64_t bits = 0;
            std::memcpy(&bits, &number, sizeof(bits));
            return {mixHash(5 ^ bits), value.IsUint64() && !value.IsInt64()};
        }
        case rapidjson::kArrayType:
        {
            ElementHash result {mixHash(6 ^ value.Size()), false};
            for (const auto& element : value.GetArray())
            {
                const auto item = hashElement(element);
                result.hash = mixHash(result.hash + item.hash);
                result.irregular = result.irregular || item.irregular;
            }
            return result;
        }
        case rapidjson::kObjectType:
        {
            uint64_t sum = 0;
            bool irregular = hasRepeatedName(value);
            for (const auto& member : value.GetObject())
            {
                const auto item = hashElement(member.value);
                sum += mixHash(hashBytes(memberName(member.name)) * 0x9e3779b97f4a7c15ULL + item.hash);
                irregular = irregular || item.irregular;
            }
            return {mixHash(7 ^ value.MemberCount() ^ sum), irregular};
        }
    }
    return {0, true};
}

struct IdentityHash
{
    size_t operator()(uint64_t hash) const noexcept { return static_cast<size_t>(hash); }
};

// Merges the source elements from srcIt on into the array dst, looking them up through a hash index of dst: the
// regular elements by hash, every candidate confirmed with valuesEqual (dst on the left, as the scan does); the
// irregular ones in a list that every regular lookup also checks, while an irregular source element is compared with
// the whole of dst. Elements added from here on enter the index. Positions, not pointers: PushBack moves the array.
// Kept out of line so that the merges that never need the index do not carry it.
[[gnu::noinline]] void mergeElementsIndexed(json::Value& dst,
                                            const json::Value& src,
                                            json::Value::ConstValueIterator srcIt,
                                            json::Allocator& allocator)
{
    std::pmr::monotonic_buffer_resource memory;
    std::pmr::unordered_multimap<uint64_t, Position, IdentityHash> regular(&memory);
    std::pmr::vector<Position> irregular(&memory);
    regular.reserve(static_cast<size_t>(dst.Size()) + static_cast<size_t>(src.End() - srcIt));

    const auto add = [&](const ElementHash& hash, Position position)
    {
        if (hash.irregular)
        {
            irregular.push_back(position);
        }
        else
        {
            regular.emplace(hash.hash, position);
        }
    };

    for (Position position = 0; position < dst.Size(); ++position)
    {
        add(hashElement(dst[position]), position);
    }

    for (; srcIt != src.End(); ++srcIt)
    {
        const auto hash = hashElement(*srcIt);
        bool found = false;
        if (hash.irregular)
        {
            for (auto dstIt = dst.Begin(); !found && dstIt != dst.End(); ++dstIt)
            {
                found = valuesEqual(*dstIt, *srcIt);
            }
        }
        else
        {
            const auto [first, last] = regular.equal_range(hash.hash);
            for (auto it = first; !found && it != last; ++it)
            {
                found = valuesEqual(dst[it->second], *srcIt);
            }
            for (auto it = irregular.begin(); !found && it != irregular.end(); ++it)
            {
                found = valuesEqual(dst[*it], *srcIt);
            }
        }

        if (!found)
        {
            json::Value cpyValue {*srcIt, allocator};
            dst.PushBack(cpyValue, allocator);
            add(hash, dst.Size() - 1);
        }
    }
}

void mergeValue(json::Value& dst, const json::Value& src, bool isRecursive, json::Allocator& allocator)
{
    if (dst.GetType() != src.GetType())
    {
        throw std::runtime_error("JSON objects of different types cannot be merged");
    }

    if (dst.IsObject())
    {
        // Members of the destination visited by the scans of this loop. Once they exceed MERGE_INDEX_SCAN_FACTOR times
        // the size of the destination, the rest of the source is merged through an index of the destination.
        size_t scanned = 0;
        for (auto srcIt = src.MemberBegin(); srcIt != src.MemberEnd(); ++srcIt)
        {
            if (scanned > Json::MERGE_INDEX_SCAN_FACTOR * static_cast<size_t>(dst.MemberCount()))
            {
                mergeMembersIndexed(dst, src, srcIt, isRecursive, allocator);
                break;
            }

            const auto found = dst.FindMember(srcIt->name);
            scanned += found == dst.MemberEnd() ? static_cast<size_t>(dst.MemberCount())
                                                : static_cast<size_t>(found - dst.MemberBegin()) + 1;
            mergeMember(dst, found, srcIt, isRecursive, allocator);
        }
    }
    else if (dst.IsArray())
    {
        // Comparisons done by the scans of this loop. Once they exceed MERGE_ARRAY_INDEX_SCAN_FACTOR times the size of
        // the destination, the rest of the source is merged through a hash index of the destination.
        size_t compared = 0;
        for (auto srcIt = src.Begin(); srcIt != src.End(); ++srcIt)
        {
            if (compared > Json::MERGE_ARRAY_INDEX_SCAN_FACTOR * static_cast<size_t>(dst.Size()))
            {
                mergeElementsIndexed(dst, src, srcIt, allocator);
                break;
            }

            auto found = false;
            for (auto dstIt = dst.Begin(); dstIt != dst.End(); ++dstIt)
            {
                ++compared;
                if (valuesEqual(*dstIt, *srcIt))
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                json::Value cpyValue {*srcIt, allocator};
                dst.PushBack(cpyValue, allocator);
            }
        }
    }
    else
    {
        throw std::runtime_error("JSON elements must be both either objects or arrays to be merged");
    }
}

} // namespace

void Json::merge(const bool isRecursive, const json::Value& source, std::string_view path)
{
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        auto* dstValue = pp.Get(m_document);
        if (dstValue)
        {
            mergeValue(*dstValue, source, isRecursive, m_document.GetAllocator());
            return;
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::merge(const bool isRecursive, const Json& other, std::string_view path)
{
    merge(isRecursive, other.m_document, path);
}

void Json::merge(const bool isRecursive, std::string_view source, std::string_view path)
{
    const auto pp = json::makePointer(source);

    if (pp.IsValid())
    {
        auto* srcValue = pp.Get(m_document);
        if (srcValue)
        {
            merge(isRecursive, *srcValue, path);
            erase(source);
            return;
        }

        throw std::runtime_error(fmt::format(PATH_NOT_FOUND_MSG, path));
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<Json> Json::getJson(std::string_view path) const
{
    std::optional<Json> retval {std::nullopt};
    const auto pp = json::makePointer(path);

    if (pp.IsValid())
    {
        auto* val = pp.Get(m_document);
        if (val)
        {
            retval = Json(*val);
        }
        return retval;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

std::optional<base::Error> Json::checkDuplicateKeys() const
{
    auto validateDuplicatedKeys = [](const json::Value& value, auto& recurRef) -> void
    {
        if (value.IsObject())
        {
            std::unordered_set<std::string> seen;
            for (auto it = value.MemberBegin(); it != value.MemberEnd(); ++it)
            {
                std::string key {it->name.GetString(), it->name.GetStringLength()};
                if (!seen.insert(key).second)
                {
                    throw std::runtime_error(fmt::format("Duplicate key '{}' found in JSON object.", key));
                }
                recurRef(it->value, recurRef);
            }
        }
        else if (value.IsArray())
        {
            for (auto it = value.Begin(); it != value.End(); ++it)
            {
                recurRef(*it, recurRef);
            }
        }
    };

    try
    {
        if (m_document.IsObject())
        {
            validateDuplicatedKeys(m_document, validateDuplicatedKeys);
        }
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("{}", e.what())};
    }

    return std::nullopt;
}

size_t Json::removeDuplicateKeys()
{
    size_t removedCount = 0;

    auto deduplicate = [&removedCount](json::Value& value, auto& recurRef) -> void
    {
        if (value.IsObject())
        {
            std::unordered_set<std::string> seen;
            for (auto it = value.MemberBegin(); it != value.MemberEnd();)
            {
                std::string key {it->name.GetString(), it->name.GetStringLength()};
                if (!seen.insert(key).second)
                {
                    it = value.EraseMember(it);
                    ++removedCount;
                }
                else
                {
                    recurRef(it->value, recurRef);
                    ++it;
                }
            }
        }
        else if (value.IsArray())
        {
            for (auto it = value.Begin(); it != value.End(); ++it)
            {
                recurRef(*it, recurRef);
            }
        }
    };

    deduplicate(m_document, deduplicate);

    return removedCount;
}

size_t Json::eraseMembersEqualTo(std::string_view path, const Json& value)
{
    const auto pp = json::makePointer(path);
    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    auto* object = pp.Get(m_document);
    if (object == nullptr || !object->IsObject())
    {
        return 0;
    }

    // Marks: 0 = different value, 1 = equal value, 2 = to erase. Allocated at the first equal member only.
    const Position count = object->MemberCount();
    const auto members = object->MemberBegin();
    std::vector<unsigned char> marks;
    for (Position position = 0; position < count; ++position)
    {
        if (valuesEqual(members[position].value, value.m_document))
        {
            if (marks.empty())
            {
                marks.resize(count, 0);
            }
            marks[position] = 1;
        }
    }
    if (marks.empty())
    {
        return 0;
    }

    // An occurrence is erased only while every earlier occurrence of its name is equal too: sort the positions by
    // (name, position) and erase the leading run of equal occurrences in each group of names.
    std::vector<Position> order(count);
    for (Position position = 0; position < count; ++position)
    {
        order[position] = position;
    }
    std::sort(order.begin(),
              order.end(),
              [&members](Position lhs, Position rhs)
              {
                  const int result =
                      internal::compareNames(memberName(members[lhs].name), memberName(members[rhs].name));
                  return result != 0 ? result < 0 : lhs < rhs;
              });

    size_t erased = 0;
    for (Position group = 0; group < count;)
    {
        const auto name = memberName(members[order[group]].name);
        Position next = group;
        bool leading = true;
        for (; next < count && internal::compareNames(memberName(members[order[next]].name), name) == 0; ++next)
        {
            leading = leading && marks[order[next]] == 1;
            if (leading)
            {
                marks[order[next]] = 2;
                ++erased;
            }
        }
        group = next;
    }
    if (erased == 0)
    {
        return 0;
    }

    // Move the kept members forward over the erased ones, in order, and drop the tail at once
    Position firstFree = 0;
    for (Position position = 0; position < count; ++position)
    {
        if (marks[position] == 2)
        {
            continue;
        }
        if (firstFree != position)
        {
            members[firstFree].name = members[position].name;
            members[firstFree].value = members[position].value;
        }
        ++firstFree;
    }
    object->EraseMember(members + firstFree, object->MemberEnd());

    return erased;
}

namespace
{

// Moves the member at position from to position to, over a member that is dropped or already moved.
void moveMember(json::Value::MemberIterator members, Position from, Position to)
{
    if (from != to)
    {
        members[to].name = members[from].name;
        members[to].value = members[from].value;
    }
}

// Ends a pass that kept firstFree members and has not looked at the members from next on yet: moves those down after
// the kept ones, in order, and drops the rest of the member array at once.
void closeGap(
    json::Value& object, json::Value::MemberIterator members, Position next, Position count, Position firstFree)
{
    for (; next < count; ++next, ++firstFree)
    {
        moveMember(members, next, firstFree);
    }
    if (firstFree != object.MemberCount())
    {
        object.EraseMember(members + firstFree, object.MemberEnd());
    }
}

// Erases, in one pass and in member order, the members of object whose name satisfies func; the kept members move
// forward over the erased ones. In recursive mode, a kept member whose value is an object is descended through the
// first kept member with the same name: the member a pointer built from that name would resolve to once the erased
// members are gone. If func throws, at any level, each level closes its gap before the exception goes on, so the
// members erased so far stay erased and the rest stay in place.
bool eraseMembersIf(json::Value& object, const std::function<bool(const std::string&)>& func, bool recursive)
{
    // Recursive mode: the first kept member with a given name is found by scanning the kept members, until the scans
    // have visited more than this many times the members of the object; from then on, through a hash index of the
    // first kept member of each name. Small objects allocate nothing.
    constexpr size_t FIRST_KEPT_SCAN_FACTOR = 4;

    const Position count = object.MemberCount();
    const auto members = object.MemberBegin();

    std::optional<std::pmr::monotonic_buffer_resource> memory;
    std::optional<std::pmr::unordered_map<std::string_view, Position>> firstKept;
    size_t scanned = 0;

    bool modified = false;
    Position firstFree = 0;
    Position next = 0;
    try
    {
        while (next < count)
        {
            const Position position = next;
            const std::string name {members[position].name.GetString(), members[position].name.GetStringLength()};
            if (func(name))
            {
                ++next;
                modified = true;
                continue;
            }

            moveMember(members, position, firstFree);
            ++next;
            const Position kept = firstFree++;
            Position first = kept;
            if (firstKept)
            {
                // Every kept member enters the index, whatever its value: it may be the first of its name. Its name
                // stays where it is for the rest of the pass, since the members only move down to positions after it.
                first = firstKept->try_emplace(memberName(members[kept].name), kept).first->second;
            }
            if (recursive && members[kept].value.IsObject())
            {
                if (!firstKept)
                {
                    const auto keptName = memberName(members[kept].name);
                    first = 0;
                    while (memberName(members[first].name) != keptName)
                    {
                        ++first;
                    }
                    scanned += static_cast<size_t>(first) + 1;
                    if (scanned > FIRST_KEPT_SCAN_FACTOR * static_cast<size_t>(count))
                    {
                        memory.emplace();
                        firstKept.emplace(&*memory);
                        firstKept->reserve(count);
                        for (Position indexed = 0; indexed <= kept; ++indexed)
                        {
                            firstKept->try_emplace(memberName(members[indexed].name), indexed);
                        }
                    }
                }
                if (members[first].value.IsObject())
                {
                    modified |= eraseMembersIf(members[first].value, func, recursive);
                }
            }
        }
    }
    catch (...)
    {
        closeGap(object, members, next, count, firstFree);
        throw;
    }

    closeGap(object, members, next, count, firstFree);
    return modified;
}

// The recursive erase with each level resolved again from the root through its path, for paths in URI-fragment form
// (#/...): there the members met while descending are read back through a fragment, percent-decoded, and a name may
// resolve to another member or make the nested path invalid.
bool eraseIfKeyByPath(json::Document& doc,
                      const std::function<bool(const std::string&)>& func,
                      bool recursive,
                      const std::string& path)
{
    bool modified = false;
    const auto pp = json::makePointer(path);

    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    auto* value = const_cast<json::Value*>(pp.Get(doc));
    if (!value || !value->IsObject())
    {
        return modified;
    }

    for (auto it = value->MemberBegin(); it != value->MemberEnd();)
    {
        const std::string name {it->name.GetString(), it->name.GetStringLength()};
        if (func(name))
        {
            it = value->EraseMember(it);
            modified = true;
        }
        else
        {
            if (recursive && it->value.IsObject())
            {
                std::string newPath {path};
                if (name.find_first_of("~/") == std::string::npos)
                {
                    newPath += '/';
                    newPath.append(name);
                }
                else
                {
                    newPath += Json::formatJsonPath(name, true);
                }
                modified |= eraseIfKeyByPath(doc, func, recursive, newPath);
            }
            ++it;
        }
    }

    return modified;
}

} // namespace

bool Json::eraseIfKey(const std::function<bool(const std::string&)>& func, bool recursive, const std::string& path)
{
    const auto pp = json::makePointer(path);

    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    auto* value = const_cast<json::Value*>(pp.Get(m_document));
    if (!value || !value->IsObject())
    {
        return false;
    }

    if (recursive && !path.empty() && path.front() == '#')
    {
        return eraseIfKeyByPath(m_document, func, recursive, path);
    }

    return eraseMembersIf(*value, func, recursive);
}

void Json::eraseRootKeysByPrefix(std::string_view prefix)
{
    if (prefix.empty())
    {
        throw std::runtime_error("Prefix must not be empty");
    }

    if (!m_document.IsObject())
    {
        throw std::runtime_error("Root JSON value is not an object");
    }

    const Position count = m_document.MemberCount();
    const auto members = m_document.MemberBegin();
    Position firstFree = 0;
    for (Position position = 0; position < count; ++position)
    {
        const auto key = memberName(members[position].name);
        if (key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0)
        {
            continue;
        }
        moveMember(members, position, firstFree);
        ++firstFree;
    }
    closeGap(m_document, members, count, count, firstFree);
}

Json Json::makeObjectJson(const std::string& key, const json::Json& value)
{
    json::Document doc(rapidjson::kObjectType);
    {
        json::Value k(key.c_str(), key.size(), doc.GetAllocator());
        json::Value v(value.m_document, doc.GetAllocator());
        doc.AddMember(k, v, doc.GetAllocator());
    }
    return Json(std::move(doc));
}

} // namespace json

#include <base/json.hpp>

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "rapidjson/memorystream.h"
#include "rapidjson/schema.h"

#include <base/logging.hpp>

namespace
{
constexpr auto INVALID_POINTER_TYPE_MSG = "Invalid pointer path '{}'";
constexpr auto PATH_NOT_FOUND_MSG = "Path '{}' not found";

// Tokens of a parsed pointer with every one marked as an object member name. rapidjson reads a token made only of
// digits as an array index, and creating it on a node that is not an object yet reserves index + 1 elements; a name
// token turns that node into an object instead. The names still point into `pointer`, which must outlive the result.
std::vector<rapidjson::Pointer::Token> asMemberTokens(const rapidjson::Pointer& pointer)
{
    std::vector<rapidjson::Pointer::Token> tokens(pointer.GetTokens(), pointer.GetTokens() + pointer.GetTokenCount());
    for (auto& token : tokens)
    {
        token.index = rapidjson::kPointerInvalidIndex;
    }
    return tokens;
}

// Exact-size copies of sub-values (Json(const rapidjson::Value&)): the pool of the new document is sized to what
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
        const rapidjson::MemoryPoolAllocator<> probe(block.get(), probeSize);
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
            rapidjson::MemoryPoolAllocator<> probe(probeChunk);
            const rapidjson::Value value(text.data(), static_cast<rapidjson::SizeType>(len), probe);
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
size_t copyFootprint(const rapidjson::Value& value, size_t inlineMax, size_t depth)
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
            return length > inlineMax ? align8((length + 1) * sizeof(rapidjson::Value::Ch)) : 0;
        }
        case rapidjson::kArrayType:
        {
            size_t bytes = align8(value.Size() * sizeof(rapidjson::Value));
            for (const auto& item : value.GetArray())
            {
                bytes += copyFootprint(item, inlineMax, depth + 1);
            }
            return bytes;
        }
        case rapidjson::kObjectType:
        {
            size_t bytes = align8(value.MemberCount() * sizeof(rapidjson::Value::Member));
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

size_t exactPoolBytes(const rapidjson::Value& value)
{
    return copyFootprint(value, maxInlineStringLength(), 0);
}
} // namespace

namespace json
{

Json::Json(const rapidjson::Value& value)
    : Json(ExactTag {}, exactPoolBytes(value))
{
    // Const strings are copied as well: the walk counts them, and the copy must not point into the source
    m_document.CopyFrom(value, m_document.GetAllocator(), /*copyConstStrings=*/true);
}

Json::Json(const rapidjson::GenericObject<true, rapidjson::Value>& object)
    : m_document {rapidjson::Document()}
{
    m_document.SetObject();
    for (auto& [key, value] : object)
    {
        m_document.GetObject().AddMember(
            {key, m_document.GetAllocator()}, {value, m_document.GetAllocator()}, m_document.GetAllocator());
    }
}

Json::Json()
    : m_document {rapidjson::Document()} {};

Json::Json(rapidjson::Document&& document)
{
    m_document = std::move(document);
}

Json::Json(const char* json)
    : m_document {rapidjson::Document()}
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
    : m_document {rapidjson::Document()}
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
} // namespace

Json::Json(CompactTag, size_t capacityHint)
    : m_compactBuffer {std::make_unique<uint8_t[]>(compactInitialCapacity(capacityHint))}
    , m_ownAllocator {std::make_unique<rapidjson::MemoryPoolAllocator<>>(
          m_compactBuffer.get(), compactInitialCapacity(capacityHint), COMPACT_CHUNK_CAPACITY)}
    , m_document {m_ownAllocator.get()}
{
}

Json::Json(ExactTag, size_t poolBytes)
    // new[] on purpose: make_unique<uint8_t[]> would zero the whole block, which CopyFrom overwrites anyway
    : m_compactBuffer {new uint8_t[poolHeaderBytes() + poolBytes]}
    , m_ownAllocator {std::make_unique<rapidjson::MemoryPoolAllocator<>>(
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
        // Replace ~ with ~0
        for (auto pos = ptrPath.find('~'); pos != std::string::npos; pos = ptrPath.find('~', pos + 2))
        {
            ptrPath.replace(pos, 1, "~0");
        }

        // Replace / with ~1
        for (auto pos = ptrPath.find('/'); pos != std::string::npos; pos = ptrPath.find('/', pos + 2))
        {
            ptrPath.replace(pos, 1, "~1");
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
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data(), ptrPath.size());
    if (fieldPtr.IsValid())
    {
        return fieldPtr.Get(m_document) != nullptr;
    }

    throw std::runtime_error(fmt::format("..", __func__, ptrPath));
}

bool Json::equals(std::string_view ptrPath, const Json& value) const
{
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data(), ptrPath.size());
    if (fieldPtr.IsValid())
    {
        const auto got {fieldPtr.Get(m_document)};
        return (got && *got == value.m_document);
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
}

bool Json::equalsString(std::string_view ptrPath, std::string_view str) const
{
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data(), ptrPath.size());
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
    const auto fieldPtr = rapidjson::Pointer(basePtrPath.data(), basePtrPath.size());
    const auto referencePtr = rapidjson::Pointer(referencePtrPath.data(), referencePtrPath.size());

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

    return (fieldValue && referenceValue && *fieldValue == *referenceValue);
}

// TODO Invert parameters to be consistent with other methods.
void Json::set(std::string_view ptrPath, const Json& value)
{
    const auto fieldPtr = rapidjson::Pointer(ptrPath.data(), ptrPath.size());
    if (fieldPtr.IsValid())
    {
        fieldPtr.Set(m_document, value.m_document);
    }
    else
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, ptrPath));
    }
}

void Json::set(std::string_view basePtrPath, std::string_view referencePtrPath)
{
    const auto fieldPtr = rapidjson::Pointer(basePtrPath.data(), basePtrPath.size());
    const auto referencePtr = rapidjson::Pointer(referencePtrPath.data(), referencePtrPath.size());

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
        fieldPtr.Set(m_document, *reference);
    }
    else
    {
        fieldPtr.Set(m_document, rapidjson::Value());
    }
}

std::optional<int> Json::getInt(std::string_view path) const
{
    std::optional<int> retval {std::nullopt};
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    auto pp = rapidjson::Pointer(path.data(), path.size());

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
    auto pp = rapidjson::Pointer(path.data(), path.size());

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
    auto pp = rapidjson::Pointer(path.data(), path.size());

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
    auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
        auto nested = [&](const auto& self, const rapidjson::Value& value, const std::string& path = "") -> void
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
    const auto pp = rapidjson::Pointer(path.data(), path.size());
    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    const rapidjson::Value* val = pp.Get(m_document);
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
using PlainWriter = rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>>;
using PrettyWriter =
    rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::ASCII<>>;

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
void collectValidNames(const rapidjson::Value& value, std::vector<NameSet>& names)
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

    SanitizingHandler(Writer& writer, const rapidjson::Value& root)
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
std::string serialize(const rapidjson::Value& value)
{
    {
        rapidjson::StringBuffer buffer;
        Writer writer(buffer);
        TailCheckingHandler<Writer> handler(writer);
        if (value.Accept(handler))
        {
            return buffer.GetString();
        }
    }

    rapidjson::StringBuffer buffer;
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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    auto pp = rapidjson::Pointer(path.data(), path.size());

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
    auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetNull());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setBool(bool value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setInt(int value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setInt64(int64_t value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setInt(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setUint64(uint64_t value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setUint64(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setFloat(float_t value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
    }
    else
    {
        throw std::runtime_error(fmt::format("[Json::setDouble(basePointerPath)] Invalid json path: '{}'", path));
    }
}

void Json::setDouble(double_t value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, value);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setStringAsMembers(std::string_view value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        const auto tokens = asMemberTokens(pp);
        const auto* data = value.data() ? value.data() : "";
        rapidjson::Value v(data, static_cast<rapidjson::SizeType>(value.size()), m_document.GetAllocator());
        rapidjson::Pointer(tokens.data(), tokens.size()).Set(m_document, v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setNullAsMembers(std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        const auto tokens = asMemberTokens(pp);
        rapidjson::Pointer(tokens.data(), tokens.size()).Set(m_document, rapidjson::Value().SetNull());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setString(std::string_view value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        const auto* data = value.data() ? value.data() : "";
        rapidjson::Value v(data, static_cast<rapidjson::SizeType>(value.size()), m_document.GetAllocator());
        pp.Set(m_document, v);
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setArray(std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetArray());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::setObject(std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        pp.Set(m_document, rapidjson::Value().SetObject());
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::appendString(std::string_view value, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        // TODO: not sure if needed, add test
        const rapidjson::size_t s1 = static_cast<rapidjson::size_t>(value.size());
        const size_t s2 = static_cast<size_t>(s1);
        if (s2 != value.size())
        {
            throw std::runtime_error(fmt::format("String is too long ({}): '{}'.", value.size(), value));
        }
        rapidjson::Value v(value.data(), s2, m_document.GetAllocator());

        auto* val = pp.Get(m_document);
        if (val)
        {
            if (!val->IsArray())
            {
                val->SetArray();
            }

            val->PushBack(v, m_document.GetAllocator());
        }
        else
        {
            rapidjson::Value vArray;
            vArray.SetArray();
            vArray.PushBack(v, m_document.GetAllocator());
            pp.Set(m_document, vArray);
        }
        return;
    }

    throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
}

void Json::appendJson(const Json& value, std::string_view path)
{
    auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        rapidjson::Value rapidValue {value.m_document, m_document.GetAllocator()};
        auto* val = pp.Get(m_document);
        if (val)
        {
            if (!val->IsArray())
            {
                val->SetArray();
            }
            val->PushBack(rapidValue, m_document.GetAllocator());
        }
        else
        {
            rapidjson::Value vArray;
            vArray.SetArray();
            vArray.PushBack(rapidValue, m_document.GetAllocator());
            pp.Set(m_document, vArray);
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
        const auto pp = rapidjson::Pointer(path.data(), path.size());

        if (pp.IsValid())
        {
            return pp.Erase(m_document);
        }

        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }
}

void Json::merge(const bool isRecursive, const rapidjson::Value& source, std::string_view path)
{
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (pp.IsValid())
    {
        auto* dstValue = pp.Get(m_document);
        if (dstValue)
        {
            if (dstValue->GetType() == source.GetType())
            {
                if (dstValue->IsObject())
                {
                    for (auto srcIt = source.MemberBegin(); srcIt != source.MemberEnd(); ++srcIt)
                    {
                        if (dstValue->HasMember(srcIt->name))
                        {
                            rapidjson::Value cpyValue {srcIt->value, m_document.GetAllocator()};
                            if (isRecursive && (srcIt->value.IsObject() || srcIt->value.IsArray()))
                            {
                                const std::string_view rawName {srcIt->name.GetString(), srcIt->name.GetStringLength()};
                                std::string newPath {path};
                                if (rawName.find_first_of("~/") == std::string_view::npos)
                                {
                                    newPath += '/';
                                    newPath.append(rawName);
                                }
                                else
                                {
                                    newPath += formatJsonPath(rawName, true);
                                }
                                merge(isRecursive, cpyValue, newPath);
                            }
                            else
                            {
                                dstValue->FindMember(srcIt->name)->value = cpyValue;
                            }
                        }
                        else
                        {
                            rapidjson::Value cpyValue {srcIt->value, m_document.GetAllocator()};
                            rapidjson::Value cpyName {srcIt->name, m_document.GetAllocator()};
                            dstValue->AddMember(cpyName, cpyValue, m_document.GetAllocator());
                        }
                    }
                }
                else if (dstValue->IsArray())
                {
                    for (auto srcIt = source.Begin(); srcIt != source.End(); ++srcIt)
                    {
                        // Find if value is already in dstValue
                        // TODO: this is inefficient, but rapidjson does not provide a way
                        // to do it.
                        auto found = false;
                        for (auto dstIt = dstValue->Begin(); dstIt != dstValue->End(); ++dstIt)
                        {
                            if (*dstIt == *srcIt)
                            {
                                found = true;
                                break;
                            }
                        }
                        if (!found)
                        {
                            rapidjson::Value cpyValue {*srcIt, m_document.GetAllocator()};
                            dstValue->PushBack(cpyValue, m_document.GetAllocator());
                        }
                    }
                }
                else
                {
                    throw std::runtime_error("JSON elements must be both either objects or arrays to be merged");
                }

                return;
            }

            throw std::runtime_error("JSON objects of different types cannot be merged");
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
    const auto pp = rapidjson::Pointer(source.data(), source.size());

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
    const auto pp = rapidjson::Pointer(path.data(), path.size());

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

std::optional<base::Error> Json::validate(const Json& schema) const
{
    rapidjson::SchemaDocument sd(schema.m_document);
    rapidjson::SchemaValidator validator(sd);

    if (!m_document.Accept(validator))
    {
        rapidjson::StringBuffer sb;
        validator.GetInvalidSchemaPointer().StringifyUriFragment(sb);
        rapidjson::StringBuffer sb2;
        validator.GetInvalidDocumentPointer().StringifyUriFragment(sb2);
        return base::Error {fmt::format(
            "Invalid JSON schema: [{}], [{}]", std::string {sb.GetString()}, std::string {sb2.GetString()})};
    }

    return std::nullopt;
}

std::optional<base::Error> Json::checkDuplicateKeys() const
{
    auto validateDuplicatedKeys = [](const rapidjson::Value& value, auto& recurRef) -> void
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

    auto deduplicate = [&removedCount](rapidjson::Value& value, auto& recurRef) -> void
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

bool Json::eraseIfKey(const std::function<bool(const std::string&)>& func, bool recursive, const std::string& path)
{
    bool modified = false;
    const auto pp = rapidjson::Pointer(path.data(), path.size());

    if (!pp.IsValid())
    {
        throw std::runtime_error(fmt::format(INVALID_POINTER_TYPE_MSG, path));
    }

    auto* value = const_cast<rapidjson::Value*>(pp.Get(m_document));
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
                    newPath += formatJsonPath(name, true);
                }
                modified |= eraseIfKey(func, recursive, newPath);
            }
            ++it;
        }
    }

    return modified;
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

    for (auto it = m_document.MemberBegin(); it != m_document.MemberEnd();)
    {
        const std::string_view key {it->name.GetString(), it->name.GetStringLength()};
        if (key.size() >= prefix.size() && key.compare(0, prefix.size(), prefix) == 0)
        {
            it = m_document.EraseMember(it);
        }
        else
        {
            ++it;
        }
    }
}

Json Json::makeObjectJson(const std::string& key, const json::Json& value)
{
    rapidjson::Document doc(rapidjson::kObjectType);
    {
        rapidjson::Value k(key.c_str(), key.size(), doc.GetAllocator());
        rapidjson::Value v(value.m_document, doc.GetAllocator());
        doc.AddMember(k, v, doc.GetAllocator());
    }
    return Json(std::move(doc));
}

} // namespace json
